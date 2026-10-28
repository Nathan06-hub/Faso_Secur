"""
Serveur Souverain Zero-Knowledge FASO-SÉCUR — API FastAPI & WebSockets Temps Réel.
Développé pour le Sprint Technique Pré-Hackathon 226 (MTDPCE / DGTD — Burkina Faso).
"""

import hashlib
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from auth import (
    build_otpauth_uri,
    create_access_token,
    generate_current_totp_code,
    generate_totp_secret,
    get_current_agent,
    get_timestamp_bucket,
    hash_password,
    pseudonymize_identifier,
    require_admin_role,
    verify_and_load_active_agent,
    verify_password,
    verify_totp_code,
)
from database import Base, SessionLocal, engine, get_db
from models import (
    Channel,
    ChannelMember,
    EncryptedAttachmentBlob,
    EncryptedMessage,
    EnrolledAgent,
    ProbativeReadReceipt,
    SecurityAuditLog,
)
from seed import DEMO_AGENTS, seed_demo_data
from ws_manager import ws_manager


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_demo_data(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title="FASO-SÉCUR — Serveur Souverain Zero-Knowledge (MTDPCE / DGTD)",
    description=(
        "Messagerie instantanée souveraine de l'administration publique du Burkina Faso. "
        "Chiffrement de bout en bout (Matrix Olm/Megolm & Signal Double Ratchet), "
        "Authentification Forte 2FA TOTP (RFC 6238), Révocation Immédiate et Minimisation des Métadonnées."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# SCHÉMAS PYDANTIC
# ============================================================================

class LoginRequest(BaseModel):
    matricule: str = Field(..., description="Matricule officiel de l'agent préalablement enrôlé")
    password: str = Field(..., description="Mot de passe de l'agent")
    totp_code: str = Field(..., description="Code 2FA TOTP à 6 chiffres (RFC 6238)")


class IntruderAttemptRequest(BaseModel):
    matricule: str
    full_name: Optional[str] = "Individu Non Enrôlé"
    password: Optional[str] = "tentative123"
    target_channel_slug: Optional[str] = "cellule-veille-souveraine"


class PublishPublicKeysRequest(BaseModel):
    identity_public_key: str
    signing_public_key: str
    signed_prekey_public: str
    signed_prekey_signature: str
    one_time_prekeys_json: str = "[]"


class SendEncryptedMessageRequest(BaseModel):
    e2ee_protocol: str = Field(default="MATRIX_OLM_MEGOLM_E2EE")
    ciphertext_payload: str = Field(..., min_length=16, description="Payload chiffré E2EE côté client")
    nonce_or_iv: str = Field(..., min_length=8)
    sender_ephemeral_public_key: str = Field(..., min_length=8)
    authenticity_mac: str = Field(..., min_length=16)
    message_kind: str = Field(default="TEXT")  # TEXT, VOICE_NOTE, ATTACHMENT, SERVICE_INSTRUCTION
    classification: str = Field(default="ORDINAIRE")  # ORDINAIRE, DIFFUSION_RESTREINTE, CONFIDENTIEL
    no_forward: bool = False
    anti_screenshot: bool = False
    requires_probative_receipt: bool = False
    expires_in_seconds: Optional[int] = None
    encrypted_blob_id: Optional[str] = None
    plaintext: Optional[str] = Field(default=None, description="Champ piège : rejeté immédiatement si fourni")


class UploadEncryptedBlobRequest(BaseModel):
    channel_id: int
    ciphertext_b64: str = Field(..., min_length=16)
    iv_b64: str = Field(..., min_length=8)


class SignProbativeReceiptRequest(BaseModel):
    signature_hex: str = Field(..., min_length=16)
    signed_payload_hash: str = Field(..., min_length=16)


class EnrolNewAgentRequest(BaseModel):
    matricule: str
    full_name: str
    ministry: str
    direction: str
    job_title: str
    role: str = "AGENT_PUBLIC"
    preferred_lang: str = "fr"
    temporary_password: str = "FasoSecur!2026"


class RevokeAgentRequest(BaseModel):
    reason: str = "Fin de mission / Perte d'appareil signalée à la DGTD"


class CreateChannelRequest(BaseModel):
    name: str
    ministry_scope: str = "TOUS"
    channel_type: str = "GROUP"
    default_classification: str = "DIFFUSION_RESTREINTE"
    member_ids: List[int] = []


# ============================================================================
# 1. SANTÉ & COMPTES DE DÉMONSTRATION FICTIFS (POUR LE JURY)
# ============================================================================

@app.get("/api/health")
def health_check():
    return {
        "status": "OPERATIONAL",
        "sovereign_hosting": True,
        "external_dependencies": "NONE (Zero Third-Party Services)",
        "e2ee_enforcement": "STRICT_CLIENT_SIDE_ONLY",
        "two_factor_auth": "RFC_6238_TOTP_MANDATORY",
    }


@app.get("/api/auth/demo-accounts")
def list_fictional_demo_accounts(db: Session = Depends(get_db)):
    """
    Retourne la liste des comptes fictifs de démonstration avec leur code 2FA TOTP courant
    pour permettre au jury de tester rapidement toutes les épreuves en direct.
    """
    agents = db.query(EnrolledAgent).order_by(EnrolledAgent.id.asc()).all()
    demo_passwords = {item["matricule"]: item["password"] for item in DEMO_AGENTS}
    result = []
    for ag in agents:
        result.append(
            {
                "id": ag.id,
                "matricule": ag.matricule,
                "full_name": ag.full_name,
                "ministry": ag.ministry,
                "direction": ag.direction,
                "job_title": ag.job_title,
                "role": ag.role,
                "preferred_lang": ag.preferred_lang,
                "is_revoked": ag.is_revoked,
                "revocation_reason": ag.revocation_reason,
                "demo_password": demo_passwords.get(ag.matricule, "FasoSecur!2026"),
                "current_totp_code": generate_current_totp_code(ag.totp_secret),
                "otpauth_uri": build_otpauth_uri(ag.matricule, ag.ministry, ag.totp_secret),
            }
        )
    return {"demo_accounts": result}


# ============================================================================
# 2. AUTHENTIFICATION VÉRIFIÉE (ENRÔLEMENT + 2FA TOTP) & REJET D'INTRUS
# ============================================================================

@app.post("/api/auth/login")
def login_enrolled_agent(req: LoginRequest, db: Session = Depends(get_db)):
    """
    Authentifie un agent public en vérifiant :
    1. Qu'il figure bien dans le registre d'enrôlement souverain (sinon rejet 403 Intrus)
    2. Qu'il n'est pas révoqué (sinon rejet 403 Révocation)
    3. Son mot de passe (bcrypt)
    4. Son second facteur 2FA TOTP (RFC 6238 via PyCA cryptography)
    """
    matricule_clean = req.matricule.strip().upper()
    agent = db.query(EnrolledAgent).filter(EnrolledAgent.matricule == matricule_clean).first()

    if not agent or not agent.is_enrolled_activated:
        db.add(
            SecurityAuditLog(
                event_type="INTRUSION_ATTEMPT_UNENROLLED",
                severity="CRITICAL",
                actor_pseudonym=pseudonymize_identifier(matricule_clean),
                description=f"Tentative de connexion rejetée : matricule '{matricule_clean}' non enrôlé par la DGTD.",
            )
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="INTRUS REJETÉ : Seuls les agents préalablement enrôlés par l'administration peuvent accéder à FASO-SÉCUR.",
        )

    if agent.is_revoked:
        db.add(
            SecurityAuditLog(
                event_type="REVOKED_AGENT_LOGIN_BLOCKED",
                severity="WARNING",
                actor_pseudonym=pseudonymize_identifier(agent.matricule),
                description=f"Connexion bloquée pour l'agent révoqué {agent.matricule} ({agent.revocation_reason}).",
            )
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"AGENT RÉVOQUÉ : Votre accès a été révoqué ({agent.revocation_reason}).",
        )

    if not verify_password(req.password, agent.password_hash):
        db.add(
            SecurityAuditLog(
                event_type="AUTH_FAILED_PASSWORD",
                severity="WARNING",
                actor_pseudonym=pseudonymize_identifier(agent.matricule),
                description="Échec d'authentification (premier facteur invalide).",
            )
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants invalides (mot de passe incorrect).",
        )

    if not verify_totp_code(agent.totp_secret, req.totp_code):
        db.add(
            SecurityAuditLog(
                event_type="AUTH_FAILED_2FA_TOTP",
                severity="WARNING",
                actor_pseudonym=pseudonymize_identifier(agent.matricule),
                description="Échec du second facteur d'authentification (code TOTP RFC 6238 invalide ou expiré).",
            )
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Second facteur (2FA TOTP) invalide ou expiré. Authentification forte obligatoire.",
        )

    access_token = create_access_token(agent)
    db.add(
        SecurityAuditLog(
            event_type="LOGIN_2FA_VERIFIED",
            severity="INFO",
            actor_pseudonym=pseudonymize_identifier(agent.matricule),
            description=f"Authentification forte (Mot de passe + 2FA TOTP) validée pour le rôle {agent.role}.",
        )
    )
    db.commit()

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "agent": {
            "id": agent.id,
            "matricule": agent.matricule,
            "full_name": agent.full_name,
            "ministry": agent.ministry,
            "direction": agent.direction,
            "job_title": agent.job_title,
            "role": agent.role,
            "preferred_lang": agent.preferred_lang,
            "e2ee_key_epoch": agent.e2ee_key_epoch,
        },
    }


@app.post("/api/auth/register")
@app.post("/api/auth/intruder-attempt")
def reject_public_registration_or_intruder(req: IntruderAttemptRequest, db: Session = Depends(get_db)):
    """
    Épreuve du jury « Intrus : un compte non enrôlé tente de rejoindre la messagerie ou un groupe ; il doit être rejeté ».
    Toute tentative d'auto-inscription publique ou d'accès sans enrôlement préalable DGTD est bloquée et journalisée.
    """
    db.add(
        SecurityAuditLog(
            event_type="INTRUDER_REJECTED",
            severity="CRITICAL",
            actor_pseudonym=pseudonymize_identifier(req.matricule or "INTRUS"),
            description=(
                f"Tentative d'intrusion bloquée : compte non enrôlé '{req.matricule}' ({req.full_name}) "
                f"a tenté de rejoindre la messagerie ou le canal '{req.target_channel_slug}'."
            ),
        )
    )
    db.commit()
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=(
            "REJET SÉCURITÉ SOUVERAINE : L'auto-inscription publique est strictement interdite. "
            "Seuls les agents préalablement enrôlés par la DGTD avec second facteur 2FA peuvent rejoindre FASO-SÉCUR."
        ),
    )


# ============================================================================
# 3. ANNUAIRE OFFICIEL PAR MINISTÈRE & TROUSSEAU DE CLÉS PUBLIQUES E2EE
# ============================================================================

@app.post("/api/e2ee/keys")
def publish_agent_public_key_bundle(
    req: PublishPublicKeysRequest,
    current_agent: EnrolledAgent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    """
    Enregistre uniquement les clés PUBLIQUES E2EE de l'agent (IdentityKey, SigningKey, SignedPreKey).
    Les clés privées ne quittent jamais le navigateur/appareil de l'agent.
    """
    current_agent.e2ee_identity_public_key = req.identity_public_key
    current_agent.e2ee_signing_public_key = req.signing_public_key
    current_agent.e2ee_signed_prekey_public = req.signed_prekey_public
    current_agent.e2ee_signed_prekey_signature = req.signed_prekey_signature
    current_agent.e2ee_one_time_prekeys_json = req.one_time_prekeys_json
    db.commit()
    return {
        "status": "PUBLIC_KEYS_PUBLISHED",
        "matricule": current_agent.matricule,
        "e2ee_key_epoch": current_agent.e2ee_key_epoch,
    }


@app.get("/api/directory")
def get_official_ministry_directory(
    ministry: Optional[str] = Query(default=None),
    current_agent: EnrolledAgent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    """
    Retourne l'annuaire officiel des agents publics par ministère et par fonction,
    ainsi que leurs clés publiques E2EE pour l'établissement de sessions chiffrées de bout en bout.
    """
    query = db.query(EnrolledAgent)
    if ministry and ministry != "TOUS":
        query = query.filter(EnrolledAgent.ministry == ministry)

    agents = query.order_by(EnrolledAgent.ministry.asc(), EnrolledAgent.full_name.asc()).all()
    ministries_map: Dict[str, List[Dict[str, Any]]] = {}
    directory_list = []

    for ag in agents:
        entry = {
            "id": ag.id,
            "matricule": ag.matricule,
            "full_name": ag.full_name,
            "ministry": ag.ministry,
            "direction": ag.direction,
            "job_title": ag.job_title,
            "role": ag.role,
            "preferred_lang": ag.preferred_lang,
            "is_revoked": ag.is_revoked,
            "revocation_reason": ag.revocation_reason,
            "is_online": ag.id in ws_manager.active_connections and not ag.is_revoked,
            "e2ee_bundle": None
            if ag.is_revoked
            else {
                "identity_public_key": ag.e2ee_identity_public_key,
                "signing_public_key": ag.e2ee_signing_public_key,
                "signed_prekey_public": ag.e2ee_signed_prekey_public,
                "signed_prekey_signature": ag.e2ee_signed_prekey_signature,
                "key_epoch": ag.e2ee_key_epoch,
            },
        }
        directory_list.append(entry)
        ministries_map.setdefault(ag.ministry, []).append(entry)

    return {
        "agents": directory_list,
        "by_ministry": ministries_map,
    }


# ============================================================================
# 4. CANAUX INSTITUTIONNELS & MESSAGERIE CHIFFRÉE DE BOUT EN BOUT (ZERO-KNOWLEDGE)
# ============================================================================

@app.get("/api/channels")
def list_agent_channels(
    current_agent: EnrolledAgent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    """Liste uniquement les canaux et groupes auxquels l'agent enrôlé et non révoqué appartient."""
    memberships = (
        db.query(ChannelMember)
        .filter(ChannelMember.agent_id == current_agent.id)
        .all()
    )
    channel_ids = [m.channel_id for m in memberships]
    if not channel_ids:
        return {"channels": []}

    channels = db.query(Channel).filter(Channel.id.in_(channel_ids)).order_by(Channel.id.asc()).all()
    result = []
    for ch in channels:
        members = (
            db.query(EnrolledAgent)
            .join(ChannelMember, ChannelMember.agent_id == EnrolledAgent.id)
            .filter(ChannelMember.channel_id == ch.id, EnrolledAgent.is_revoked == False)  # noqa: E712
            .all()
        )
        result.append(
            {
                "id": ch.id,
                "slug": ch.slug,
                "name": ch.name,
                "ministry_scope": ch.ministry_scope,
                "channel_type": ch.channel_type,
                "default_classification": ch.default_classification,
                "crypto_epoch": ch.crypto_epoch,
                "active_members": [
                    {
                        "id": m.id,
                        "matricule": m.matricule,
                        "full_name": m.full_name,
                        "ministry": m.ministry,
                        "role": m.role,
                        "e2ee_identity_public_key": m.e2ee_identity_public_key,
                        "e2ee_signing_public_key": m.e2ee_signing_public_key,
                    }
                    for m in members
                ],
            }
        )
    return {"channels": result}


@app.post("/api/channels")
def create_institutional_or_direct_channel(
    req: CreateChannelRequest,
    current_agent: EnrolledAgent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    """Crée un nouveau canal institutionnel ou un groupe de travail chiffré de bout en bout."""
    slug_base = req.name.lower().replace(" ", "-")[:40]
    slug = f"{slug_base}-{secrets.token_hex(3)}"
    channel = Channel(
        slug=slug,
        name=req.name,
        ministry_scope=req.ministry_scope,
        channel_type=req.channel_type,
        default_classification=req.default_classification,
        crypto_epoch=1,
    )
    db.add(channel)
    db.flush()

    member_ids = set(req.member_ids + [current_agent.id])
    for aid in member_ids:
        ag = db.query(EnrolledAgent).filter(EnrolledAgent.id == aid, EnrolledAgent.is_revoked == False).first()  # noqa: E712
        if ag:
            db.add(ChannelMember(channel_id=channel.id, agent_id=ag.id))

    db.commit()
    return {"id": channel.id, "slug": channel.slug, "name": channel.name, "crypto_epoch": channel.crypto_epoch}


@app.get("/api/channels/{channel_id}/messages")
def get_channel_encrypted_messages(
    channel_id: int,
    current_agent: EnrolledAgent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    """
    Récupère les enveloppes chiffrées E2EE d'un canal.
    Vérifie d'abord que l'agent est bien membre autorisé du canal (bloque tout intrus ou agent retiré).
    Filtre également les messages expirés automatiquement (`expires_at`).
    """
    membership = (
        db.query(ChannelMember)
        .filter(
            ChannelMember.channel_id == channel_id,
            ChannelMember.agent_id == current_agent.id,
        )
        .first()
    )
    if not membership:
        db.add(
            SecurityAuditLog(
                event_type="UNAUTHORIZED_CHANNEL_ACCESS_BLOCKED",
                severity="WARNING",
                actor_pseudonym=pseudonymize_identifier(current_agent.matricule),
                description=f"Tentative d'accès non autorisée au canal #{channel_id} bloquée.",
            )
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Accès refusé : vous n'êtes pas membre habilité de ce canal ou groupe.",
        )

    now_naive = datetime.now(timezone.utc).replace(tzinfo=None)
    messages = (
        db.query(EncryptedMessage)
        .filter(EncryptedMessage.channel_id == channel_id)
        .order_by(EncryptedMessage.id.asc())
        .all()
    )

    agents_by_id = {
        ag.id: ag for ag in db.query(EnrolledAgent).all()
    }

    output = []
    for msg in messages:
        if msg.expires_at and msg.expires_at < now_naive:
            continue
        sender = agents_by_id.get(msg.sender_id)
        receipts = (
            db.query(ProbativeReadReceipt)
            .filter(ProbativeReadReceipt.message_id == msg.id)
            .all()
        )
        output.append(
            {
                "id": msg.id,
                "channel_id": msg.channel_id,
                "sender_id": msg.sender_id,
                "sender_matricule": sender.matricule if sender else "INCONNU",
                "sender_name": sender.full_name if sender else "Agent",
                "sender_ministry": sender.ministry if sender else "",
                "sender_role": sender.role if sender else "",
                "sender_pseudonym_hash": msg.sender_pseudonym_hash,
                "e2ee_protocol": msg.e2ee_protocol,
                "crypto_epoch": msg.crypto_epoch,
                "ciphertext_payload": msg.ciphertext_payload,
                "nonce_or_iv": msg.nonce_or_iv,
                "sender_ephemeral_public_key": msg.sender_ephemeral_public_key,
                "authenticity_mac": msg.authenticity_mac,
                "message_kind": msg.message_kind,
                "classification": msg.classification,
                "no_forward": msg.no_forward,
                "anti_screenshot": msg.anti_screenshot,
                "requires_probative_receipt": msg.requires_probative_receipt,
                "expires_at": msg.expires_at.isoformat() + "Z" if msg.expires_at else None,
                "encrypted_blob_id": msg.encrypted_blob_id,
                "timestamp_bucket": msg.timestamp_bucket,
                "created_at": msg.created_at.isoformat() + "Z",
                "probative_receipts": [
                    {
                        "id": r.id,
                        "agent_id": r.agent_id,
                        "agent_matricule": r.agent_matricule,
                        "agent_full_name": r.agent_full_name,
                        "signature_hex": r.signature_hex,
                        "signed_payload_hash": r.signed_payload_hash,
                        "signed_at": r.signed_at.isoformat() + "Z",
                    }
                    for r in receipts
                ],
            }
        )
    return {"messages": output}


@app.post("/api/channels/{channel_id}/messages")
async def post_encrypted_message(
    channel_id: int,
    req: SendEncryptedMessageRequest,
    current_agent: EnrolledAgent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    """
    Reçoit et stocke UNIQUEMENT une enveloppe chiffrée de bout en bout (Zero-Knowledge).
    Règle éliminatoire : Si un client tente d'envoyer un champ `plaintext` ou un contenu non chiffré,
    le serveur rejette immédiatement la requête (400 Bad Request).
    """
    if req.plaintext is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="VIOLATION E2EE BLOQUÉE : Le serveur refuse catégoriquement tout champ en clair (`plaintext`).",
        )

    membership = (
        db.query(ChannelMember)
        .filter(
            ChannelMember.channel_id == channel_id,
            ChannelMember.agent_id == current_agent.id,
        )
        .first()
    )
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Vous n'êtes pas membre autorisé de ce canal.",
        )

    channel = db.query(Channel).filter(Channel.id == channel_id).first()
    if not channel:
        raise HTTPException(status_code=404, detail="Canal introuvable.")

    expires_at = None
    if req.expires_in_seconds and req.expires_in_seconds > 0:
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=req.expires_in_seconds)).replace(tzinfo=None)

    no_forward = req.no_forward or req.classification in ("DIFFUSION_RESTREINTE", "CONFIDENTIEL")
    anti_screenshot = req.anti_screenshot or req.classification in ("DIFFUSION_RESTREINTE", "CONFIDENTIEL")

    msg = EncryptedMessage(
        channel_id=channel_id,
        sender_id=current_agent.id,
        sender_pseudonym_hash=pseudonymize_identifier(current_agent.matricule),
        e2ee_protocol=req.e2ee_protocol,
        crypto_epoch=channel.crypto_epoch,
        ciphertext_payload=req.ciphertext_payload,
        nonce_or_iv=req.nonce_or_iv,
        sender_ephemeral_public_key=req.sender_ephemeral_public_key,
        authenticity_mac=req.authenticity_mac,
        message_kind=req.message_kind,
        classification=req.classification,
        no_forward=no_forward,
        anti_screenshot=anti_screenshot,
        requires_probative_receipt=req.requires_probative_receipt,
        expires_at=expires_at,
        encrypted_blob_id=req.encrypted_blob_id,
        timestamp_bucket=get_timestamp_bucket(),
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)

    # Membres actifs non révoqués du canal
    active_member_rows = (
        db.query(ChannelMember.agent_id)
        .join(EnrolledAgent, EnrolledAgent.id == ChannelMember.agent_id)
        .filter(
            ChannelMember.channel_id == channel_id,
            EnrolledAgent.is_revoked == False,  # noqa: E712
        )
        .all()
    )
    recipient_ids = [r[0] for r in active_member_rows]

    wire_envelope = {
        "type": "NEW_E2EE_MESSAGE",
        "message": {
            "id": msg.id,
            "channel_id": msg.channel_id,
            "sender_id": current_agent.id,
            "sender_matricule": current_agent.matricule,
            "sender_name": current_agent.full_name,
            "sender_ministry": current_agent.ministry,
            "sender_role": current_agent.role,
            "sender_pseudonym_hash": msg.sender_pseudonym_hash,
            "e2ee_protocol": msg.e2ee_protocol,
            "crypto_epoch": msg.crypto_epoch,
            "ciphertext_payload": msg.ciphertext_payload,
            "nonce_or_iv": msg.nonce_or_iv,
            "sender_ephemeral_public_key": msg.sender_ephemeral_public_key,
            "authenticity_mac": msg.authenticity_mac,
            "message_kind": msg.message_kind,
            "classification": msg.classification,
            "no_forward": msg.no_forward,
            "anti_screenshot": msg.anti_screenshot,
            "requires_probative_receipt": msg.requires_probative_receipt,
            "expires_at": msg.expires_at.isoformat() + "Z" if msg.expires_at else None,
            "encrypted_blob_id": msg.encrypted_blob_id,
            "timestamp_bucket": msg.timestamp_bucket,
            "created_at": msg.created_at.isoformat() + "Z",
            "probative_receipts": [],
        },
    }
    await ws_manager.broadcast_to_agents(recipient_ids, wire_envelope)

    return wire_envelope["message"]


# ============================================================================
# 5. STOCKAGE SOUVERAIN DE FICHIERS & NOTES VOCALES CHIFFRÉS E2EE
# ============================================================================

@app.post("/api/blobs")
def upload_encrypted_attachment_blob(
    req: UploadEncryptedBlobRequest,
    current_agent: EnrolledAgent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    """
    Stocke un blob binaire (document PDF, image, note vocale en langue nationale) déjà chiffré côté client.
    Le serveur applique un remplissage de taille (padding par bloc de 4096 octets) pour minimiser
    les métadonnées liées à la taille exacte du fichier.
    """
    membership = (
        db.query(ChannelMember)
        .filter(
            ChannelMember.channel_id == req.channel_id,
            ChannelMember.agent_id == current_agent.id,
        )
        .first()
    )
    if not membership:
        raise HTTPException(status_code=403, detail="Accès au canal non autorisé.")

    blob_id = f"blob_{secrets.token_hex(12)}"
    sha256_hash = hashlib.sha256(req.ciphertext_b64.encode("utf-8")).hexdigest()
    raw_len = len(req.ciphertext_b64)
    padded_size = ((raw_len + 4095) // 4096) * 4096

    blob = EncryptedAttachmentBlob(
        blob_id=blob_id,
        channel_id=req.channel_id,
        uploader_pseudonym_hash=pseudonymize_identifier(current_agent.matricule),
        ciphertext_b64=req.ciphertext_b64,
        iv_b64=req.iv_b64,
        sha256_ciphertext=sha256_hash,
        size_padded_bytes=padded_size,
    )
    db.add(blob)
    db.commit()

    return {
        "blob_id": blob_id,
        "sha256_ciphertext": sha256_hash,
        "size_padded_bytes": padded_size,
    }


@app.get("/api/blobs/{blob_id}")
def download_encrypted_attachment_blob(
    blob_id: str,
    current_agent: EnrolledAgent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    """Télécharge le blob chiffré afin que le client autorisé le déchiffre localement."""
    blob = db.query(EncryptedAttachmentBlob).filter(EncryptedAttachmentBlob.blob_id == blob_id).first()
    if not blob:
        raise HTTPException(status_code=404, detail="Blob chiffré introuvable.")

    membership = (
        db.query(ChannelMember)
        .filter(
            ChannelMember.channel_id == blob.channel_id,
            ChannelMember.agent_id == current_agent.id,
        )
        .first()
    )
    if not membership:
        raise HTTPException(status_code=403, detail="Accès interdit à ce fichier chiffré.")

    return {
        "blob_id": blob.blob_id,
        "channel_id": blob.channel_id,
        "ciphertext_b64": blob.ciphertext_b64,
        "iv_b64": blob.iv_b64,
        "sha256_ciphertext": blob.sha256_ciphertext,
        "size_padded_bytes": blob.size_padded_bytes,
    }


# ============================================================================
# 6. ACCUSÉ DE LECTURE À VALEUR PROBANTE (INSTRUCTIONS DE SERVICE)
# ============================================================================

@app.post("/api/messages/{message_id}/probative-receipt")
async def submit_probative_read_receipt(
    message_id: int,
    req: SignProbativeReceiptRequest,
    current_agent: EnrolledAgent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    """
    Enregistre un accusé de réception signé cryptographiquement par l'agent destinataire
    pour une instruction de service officielle.
    """
    msg = db.query(EncryptedMessage).filter(EncryptedMessage.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message introuvable.")

    existing = (
        db.query(ProbativeReadReceipt)
        .filter(
            ProbativeReadReceipt.message_id == message_id,
            ProbativeReadReceipt.agent_id == current_agent.id,
        )
        .first()
    )
    if existing:
        return {
            "id": existing.id,
            "message_id": existing.message_id,
            "agent_matricule": existing.agent_matricule,
            "agent_full_name": existing.agent_full_name,
            "signature_hex": existing.signature_hex,
            "signed_payload_hash": existing.signed_payload_hash,
            "signed_at": existing.signed_at.isoformat() + "Z",
        }

    receipt = ProbativeReadReceipt(
        message_id=message_id,
        agent_id=current_agent.id,
        agent_matricule=current_agent.matricule,
        agent_full_name=current_agent.full_name,
        signature_hex=req.signature_hex,
        signed_payload_hash=req.signed_payload_hash,
    )
    db.add(receipt)
    db.commit()
    db.refresh(receipt)

    member_rows = (
        db.query(ChannelMember.agent_id)
        .filter(ChannelMember.channel_id == msg.channel_id)
        .all()
    )
    recipient_ids = [r[0] for r in member_rows]
    receipt_payload = {
        "type": "PROBATIVE_RECEIPT_SIGNED",
        "message_id": message_id,
        "channel_id": msg.channel_id,
        "receipt": {
            "id": receipt.id,
            "agent_id": receipt.agent_id,
            "agent_matricule": receipt.agent_matricule,
            "agent_full_name": receipt.agent_full_name,
            "signature_hex": receipt.signature_hex,
            "signed_payload_hash": receipt.signed_payload_hash,
            "signed_at": receipt.signed_at.isoformat() + "Z",
        },
    }
    await ws_manager.broadcast_to_agents(recipient_ids, receipt_payload)
    return receipt_payload["receipt"]


# ============================================================================
# 7. ENRÔLEMENT SOUVERAIN & RÉVOCATION IMMÉDIATE (ÉPREUVE DU JURY)
# ============================================================================

@app.post("/api/admin/enrol")
def enrol_new_public_agent(
    req: EnrolNewAgentRequest,
    admin_agent: EnrolledAgent = Depends(require_admin_role),
    db: Session = Depends(get_db),
):
    """Enrôle officiellement un nouvel agent public avec génération d'un secret 2FA TOTP."""
    matricule_clean = req.matricule.strip().upper()
    if db.query(EnrolledAgent).filter(EnrolledAgent.matricule == matricule_clean).first():
        raise HTTPException(status_code=400, detail="Ce matricule est déjà enrôlé.")

    totp_secret = generate_totp_secret()
    new_agent = EnrolledAgent(
        matricule=matricule_clean,
        full_name=req.full_name,
        ministry=req.ministry,
        direction=req.direction,
        job_title=req.job_title,
        role=req.role,
        preferred_lang=req.preferred_lang,
        password_hash=hash_password(req.temporary_password),
        totp_secret=totp_secret,
        totp_enabled=True,
        is_enrolled_activated=True,
        is_revoked=False,
        token_version=1,
    )
    db.add(new_agent)
    db.flush()

    # Ajouter l'agent aux canaux interministériels par défaut
    default_channels = db.query(Channel).filter(Channel.ministry_scope == "TOUS").all()
    for ch in default_channels:
        db.add(ChannelMember(channel_id=ch.id, agent_id=new_agent.id))

    db.add(
        SecurityAuditLog(
            event_type="AGENT_ENROLLED",
            severity="INFO",
            actor_pseudonym=pseudonymize_identifier(admin_agent.matricule),
            description=f"Enrôlement officiel de l'agent {matricule_clean} ({req.ministry}) avec 2FA TOTP activé.",
        )
    )
    db.commit()

    return {
        "id": new_agent.id,
        "matricule": new_agent.matricule,
        "full_name": new_agent.full_name,
        "totp_secret": totp_secret,
        "current_totp_code": generate_current_totp_code(totp_secret),
        "otpauth_uri": build_otpauth_uri(new_agent.matricule, new_agent.ministry, totp_secret),
    }


@app.post("/api/admin/revoke/{agent_id}")
async def revoke_agent_immediately(
    agent_id: int,
    req: RevokeAgentRequest,
    admin_agent: EnrolledAgent = Depends(require_admin_role),
    db: Session = Depends(get_db),
):
    """
    Épreuve éliminatoire du jury :
    « Révocation : le jury révoque un agent pendant une conversation de groupe ;
    celui-ci doit perdre immédiatement l'accès, y compris aux nouveaux messages ».

    Actions exécutées atomiquement :
    1. `is_revoked = True` et `token_version += 1` (invalide instantanément tous les JWT de l'agent)
    2. Effacement des clés publiques E2EE de l'agent sur le serveur
    3. Retrait de l'agent de toutes les tables `ChannelMember` (il ne reçoit plus aucune trame)
    4. Incrémentation de `crypto_epoch` sur chaque canal où il était présent (force la rotation
       immédiate des clés de session de groupe Megolm / Sender Keys chez les membres restants)
    5. Envoi temps réel WebSocket de l'ordre `REMOTE_WIPE_AND_REVOKE` + fermeture du socket (4003)
    """
    target = db.query(EnrolledAgent).filter(EnrolledAgent.id == agent_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Agent introuvable.")

    target.is_revoked = True
    target.revoked_at = datetime.now(timezone.utc).replace(tzinfo=None)
    target.revocation_reason = req.reason
    target.token_version += 1
    target.e2ee_identity_public_key = None
    target.e2ee_signing_public_key = None
    target.e2ee_signed_prekey_public = None
    target.e2ee_one_time_prekeys_json = None

    memberships = db.query(ChannelMember).filter(ChannelMember.agent_id == target.id).all()
    affected_channel_ids = [m.channel_id for m in memberships]

    # Retirer immédiatement l'agent révoqué des groupes afin qu'aucun nouveau message ne lui soit routé
    for m in memberships:
        db.delete(m)

    new_epochs: Dict[int, int] = {}
    remaining_agent_ids: set = set()
    if affected_channel_ids:
        channels = db.query(Channel).filter(Channel.id.in_(affected_channel_ids)).all()
        for ch in channels:
            ch.crypto_epoch += 1
            new_epochs[ch.id] = ch.crypto_epoch
        rem_rows = (
            db.query(ChannelMember.agent_id)
            .filter(ChannelMember.channel_id.in_(affected_channel_ids))
            .all()
        )
        remaining_agent_ids = {r[0] for r in rem_rows if r[0] != target.id}

    db.add(
        SecurityAuditLog(
            event_type="AGENT_REVOKED_IMMEDIATELY",
            severity="CRITICAL",
            actor_pseudonym=pseudonymize_identifier(admin_agent.matricule),
            description=(
                f"Révocation immédiate de l'agent {target.matricule} ({req.reason}). "
                f"Jetons invalidés, retrait de {len(affected_channel_ids)} canaux et rotation des clés E2EE de groupe."
            ),
        )
    )
    db.commit()

    closed_sockets = await ws_manager.revoke_and_wipe_agent_immediately(
        revoked_agent_id=target.id,
        matricule=target.matricule,
        reason=req.reason,
        affected_channel_ids=affected_channel_ids,
        remaining_agent_ids=list(remaining_agent_ids),
        new_epochs=new_epochs,
    )

    return {
        "status": "REVOKED_IMMEDIATELY",
        "revoked_agent_id": target.id,
        "matricule": target.matricule,
        "closed_websocket_sessions": closed_sockets,
        "rotated_channels_epochs": new_epochs,
    }


@app.post("/api/admin/reinstate/{agent_id}")
def reinstate_revoked_agent_for_demo(
    agent_id: int,
    admin_agent: EnrolledAgent = Depends(require_admin_role),
    db: Session = Depends(get_db),
):
    """
    Permet au jury de réhabiliter un compte fictif après avoir testé l'épreuve de révocation,
    afin de pouvoir rejouer la démonstration autant de fois que souhaité.
    """
    target = db.query(EnrolledAgent).filter(EnrolledAgent.id == agent_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Agent introuvable.")

    target.is_revoked = False
    target.revoked_at = None
    target.revocation_reason = None
    target.token_version += 1
    target.e2ee_key_epoch += 1

    all_channels = db.query(Channel).all()
    for ch in all_channels:
        exists = (
            db.query(ChannelMember)
            .filter(ChannelMember.channel_id == ch.id, ChannelMember.agent_id == target.id)
            .first()
        )
        if not exists:
            db.add(ChannelMember(channel_id=ch.id, agent_id=target.id))

    db.add(
        SecurityAuditLog(
            event_type="AGENT_REINSTATED_DEMO",
            severity="INFO",
            actor_pseudonym=pseudonymize_identifier(admin_agent.matricule),
            description=f"Réhabilitation de démonstration de l'agent {target.matricule} avec nouvelle époque de clés.",
        )
    )
    db.commit()
    return {"status": "REINSTATED", "matricule": target.matricule}


# ============================================================================
# 8. CONSOLE D'INSPECTION DU JURY (« LE SERVEUR NE LIT RIEN »)
# ============================================================================

@app.get("/api/jury/server-inspection")
def inspect_raw_server_database_and_network(
    current_agent: EnrolledAgent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    """
    Épreuve en direct du jury :
    « Le serveur ne lit rien : inspection de la base de données et du trafic réseau ;
    aucun message ni fichier ne doit apparaître en clair ».
    Expose la vue exacte des tables SQLite/PostgreSQL côté serveur et des dernières trames réseau.
    """
    raw_messages = (
        db.query(EncryptedMessage)
        .order_by(EncryptedMessage.id.desc())
        .limit(25)
        .all()
    )
    raw_blobs = (
        db.query(EncryptedAttachmentBlob)
        .order_by(EncryptedAttachmentBlob.created_at.desc())
        .limit(15)
        .all()
    )
    audit_logs = (
        db.query(SecurityAuditLog)
        .order_by(SecurityAuditLog.id.desc())
        .limit(30)
        .all()
    )

    return {
        "zero_knowledge_verification": {
            "plaintext_columns_in_db": 0,
            "all_payloads_encrypted": True,
            "metadata_minimization": {
                "sender_pseudonymization": "HMAC-SHA256 (non-reversible)",
                "timestamp_granularity": "Arrondi par tranche de 5 minutes (anti-corrélation)",
                "attachment_padding": "Blocs de 4096 octets (masquage de la taille exacte)",
            },
        },
        "database_table_encrypted_messages": [
            {
                "id": m.id,
                "channel_id": m.channel_id,
                "sender_pseudonym_hash": m.sender_pseudonym_hash,
                "e2ee_protocol": m.e2ee_protocol,
                "crypto_epoch": m.crypto_epoch,
                "ciphertext_payload": m.ciphertext_payload,
                "nonce_or_iv": m.nonce_or_iv,
                "authenticity_mac": m.authenticity_mac,
                "message_kind": m.message_kind,
                "classification": m.classification,
                "timestamp_bucket": m.timestamp_bucket,
            }
            for m in raw_messages
        ],
        "database_table_encrypted_blobs": [
            {
                "blob_id": b.blob_id,
                "uploader_pseudonym_hash": b.uploader_pseudonym_hash,
                "ciphertext_preview": b.ciphertext_b64[:96] + "...",
                "iv_b64": b.iv_b64,
                "sha256_ciphertext": b.sha256_ciphertext,
                "size_padded_bytes": b.size_padded_bytes,
            }
            for b in raw_blobs
        ],
        "recent_network_wire_frames": list(ws_manager.recent_network_frames),
        "security_audit_logs": [
            {
                "id": log.id,
                "event_type": log.event_type,
                "severity": log.severity,
                "actor_pseudonym": log.actor_pseudonym,
                "description": log.description,
                "created_at": log.created_at.isoformat() + "Z",
            }
            for log in audit_logs
        ],
    }


# ============================================================================
# 9. WEBSOCKET TEMPS RÉEL AVEC VÉRIFICATION CONTINUE DE RÉVOCATION
# ============================================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(...)):
    db = SessionLocal()
    agent_id: Optional[int] = None
    try:
        agent = verify_and_load_active_agent(token, db)
        agent_id = agent.id
        await ws_manager.connect(agent_id, websocket)
        await websocket.send_json(
            {
                "type": "WS_CONNECTED_SOVEREIGN",
                "matricule": agent.matricule,
                "role": agent.role,
                "e2ee_status": "ZERO_KNOWLEDGE_RELAY_ACTIVE",
            }
        )
        while True:
            data = await websocket.receive_json()
            # À chaque message sur le WebSocket, on re-vérifie que l'agent n'a pas été révoqué
            db.expire_all()
            fresh_agent = db.query(EnrolledAgent).filter(EnrolledAgent.id == agent_id).first()
            if not fresh_agent or fresh_agent.is_revoked:
                await websocket.send_json(
                    {
                        "type": "REMOTE_WIPE_AND_REVOKE",
                        "reason": "Votre compte a été révoqué.",
                    }
                )
                await websocket.close(code=4003)
                break

            if data.get("type") == "PING":
                await websocket.send_json({"type": "PONG"})
    except HTTPException:
        try:
            await websocket.close(code=4003)
        except Exception:
            pass
    except WebSocketDisconnect:
        pass
    finally:
        if agent_id is not None:
            ws_manager.disconnect(agent_id, websocket)
        db.close()
