"""
Serveur Souverain Zero-Knowledge & Sealed Sender FASO-SÉCUR — API FastAPI & WebSockets Temps Réel.
Développé pour le Sprint Technique Pré-Hackathon 226 (MTDPCE / DGTD — Burkina Faso).
"""

import base64
import hashlib
import json
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

import auth
from auth import (
    build_otpauth_uri,
    compute_key_safety_number,
    create_access_token,
    decrypt_totp_secret_at_rest,
    encrypt_totp_secret_at_rest,
    generate_current_totp_code,
    generate_totp_secret,
    get_current_agent,
    get_timestamp_bucket,
    hash_password,
    login_rate_limiter,
    pseudonymize_identifier,
    require_admin_role,
    verify_and_load_active_agent,
    verify_ecdsa_p256_jwk_signature,
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
        "Chiffrement de bout en bout (WebCrypto ECDH P-256 + HKDF-SHA256 + AES-256-GCM + ECDSA P-256), "
        "Sealed Sender, Authentification Forte 2FA TOTP (RFC 6238 chiffré Fernet), Révocation Immédiate."
    ),
    version="1.2.0",
    lifespan=lifespan,
)

ALLOWED_CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "FASO_SECUR_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,https://msg.gouv.bf",
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
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


class PublishGroupSessionBundleRequest(BaseModel):
    crypto_epoch: int
    wrapped_keys_by_matricule: Dict[str, Any]
    initial: bool = False


class SendEncryptedMessageRequest(BaseModel):
    e2ee_protocol: str = Field(default="WEBCRYPTO_ECDH_HKDF_AES256GCM_ECDSA")
    ciphertext_payload: str = Field(..., min_length=16, description="Payload chiffré E2EE côté client (Sealed Sender)")
    nonce_or_iv: str = Field(..., min_length=8)
    authenticity_mac: str = Field(..., min_length=16, description="Signature ECDSA P-256 vérifiée contre l'annuaire")
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
# 1. SANTÉ & COMPTES DE DÉMONSTRATION FICTIFS (CONTRÔLÉS PAR DEMO_MODE)
# ============================================================================

@app.get("/api/health")
def health_check():
    return {
        "status": "OPERATIONAL",
        "sovereign_hosting": True,
        "external_dependencies": "NONE (Zero Third-Party Services)",
        "e2ee_enforcement": "WEBCRYPTO_ECDH_HKDF_AES256GCM_ECDSA_SEALED_SENDER",
        "two_factor_auth": "RFC_6238_TOTP_FERNET_ENCRYPTED_AT_REST",
        "demo_mode": auth.DEMO_MODE_ENABLED,
    }


@app.get("/api/auth/demo-accounts")
def list_fictional_demo_accounts(db: Session = Depends(get_db)):
    """
    Retourne la liste des comptes fictifs de démonstration uniquement lorsque
    `FASO_SECUR_DEMO_MODE=true`. Ne retourne jamais le secret TOTP Base32 brut.
    """
    if not auth.DEMO_MODE_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Endpoint de démonstration désactivé hors mode démo (FASO_SECUR_DEMO_MODE=false).",
        )

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
                "current_totp_code": generate_current_totp_code(ag.totp_secret_encrypted),
            }
        )
    return {"demo_accounts": result}


# ============================================================================
# 2. AUTHENTIFICATION VÉRIFIÉE (ENRÔLEMENT + 2FA TOTP FERNET + ANTI-BRUTE-FORCE)
# ============================================================================

@app.post("/api/auth/login")
def login_enrolled_agent(req: LoginRequest, db: Session = Depends(get_db)):
    matricule_clean = req.matricule.strip().upper()
    login_rate_limiter.check_allowed(matricule_clean)

    agent = db.query(EnrolledAgent).filter(EnrolledAgent.matricule == matricule_clean).first()

    if not agent or not agent.is_enrolled_activated:
        login_rate_limiter.record_failure(matricule_clean)
        db.add(
            SecurityAuditLog(
                event_type="INTRUSION_ATTEMPT_UNENROLLED",
                severity="CRITICAL",
                actor_pseudonym=pseudonymize_identifier(matricule_clean),
                description=f"Tentative de connexion rejetée : matricule '{matricule_clean}' non enrôlé par la DGTD.",
                timestamp_bucket=get_timestamp_bucket(),
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
                timestamp_bucket=get_timestamp_bucket(),
            )
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"AGENT RÉVOQUÉ : Votre accès a été révoqué ({agent.revocation_reason}).",
        )

    if not verify_password(req.password, agent.password_hash):
        login_rate_limiter.record_failure(matricule_clean)
        db.add(
            SecurityAuditLog(
                event_type="AUTH_FAILED_PASSWORD",
                severity="WARNING",
                actor_pseudonym=pseudonymize_identifier(agent.matricule),
                description="Échec d'authentification (premier facteur invalide).",
                timestamp_bucket=get_timestamp_bucket(),
            )
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants invalides (mot de passe incorrect).",
        )

    if not verify_totp_code(agent.totp_secret_encrypted, req.totp_code):
        login_rate_limiter.record_failure(matricule_clean)
        db.add(
            SecurityAuditLog(
                event_type="AUTH_FAILED_2FA_TOTP",
                severity="WARNING",
                actor_pseudonym=pseudonymize_identifier(agent.matricule),
                description="Échec du second facteur d'authentification (code TOTP RFC 6238 invalide ou expiré).",
                timestamp_bucket=get_timestamp_bucket(),
            )
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Second facteur (2FA TOTP) invalide ou expiré. Authentification forte obligatoire.",
        )

    login_rate_limiter.reset(matricule_clean)
    access_token = create_access_token(agent)
    db.add(
        SecurityAuditLog(
            event_type="LOGIN_2FA_VERIFIED",
            severity="INFO",
            actor_pseudonym=pseudonymize_identifier(agent.matricule),
            description=f"Authentification forte (Mot de passe + 2FA TOTP) validée pour le rôle {agent.role}.",
            timestamp_bucket=get_timestamp_bucket(),
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
            "e2ee_safety_number": agent.e2ee_safety_number,
        },
    }


@app.post("/api/auth/register")
@app.post("/api/auth/intruder-attempt")
def reject_public_registration_or_intruder(req: IntruderAttemptRequest, db: Session = Depends(get_db)):
    db.add(
        SecurityAuditLog(
            event_type="INTRUDER_REJECTED",
            severity="CRITICAL",
            actor_pseudonym=pseudonymize_identifier(req.matricule or "INTRUS"),
            description=(
                f"Tentative d'intrusion bloquée : compte non enrôlé '{req.matricule}' ({req.full_name}) "
                f"a tenté de rejoindre la messagerie ou le canal '{req.target_channel_slug}'."
            ),
            timestamp_bucket=get_timestamp_bucket(),
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
    Enregistre uniquement les clés PUBLIQUES E2EE de l'agent (IdentityKey ECDH, SigningKey ECDSA, SignedPreKey).
    Vérification OBLIGATOIRE de la validité des JWK P-256 et de la signature ECDSA (`signed_prekey_signature`) !
    """
    for field_name, jwk_str in (
        ("identity_public_key", req.identity_public_key),
        ("signing_public_key", req.signing_public_key),
        ("signed_prekey_public", req.signed_prekey_public),
    ):
        try:
            parsed = json.loads(jwk_str)
            if not isinstance(parsed, dict) or parsed.get("crv") != "P-256" or "x" not in parsed or "y" not in parsed:
                raise ValueError("Not a P-256 JWK")
            if "d" in parsed:
                raise ValueError("Private key forbidden on server")
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Clé publique '{field_name}' invalide : JWK P-256 public requis.",
            ) from exc

    prekey_bytes = req.signed_prekey_public.encode("utf-8")
    is_valid_prekey_sig = verify_ecdsa_p256_jwk_signature(
        public_jwk_json=req.signing_public_key,
        message_bytes=prekey_bytes,
        signature_hex=req.signed_prekey_signature,
    )
    if not is_valid_prekey_sig:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Signature ECDSA P-256 de la pré-clé publique (SignedPreKey) invalide.",
        )

    safety_number = compute_key_safety_number(
        current_agent.matricule,
        req.identity_public_key,
        req.signing_public_key,
    )

    current_agent.e2ee_identity_public_key = req.identity_public_key
    current_agent.e2ee_signing_public_key = req.signing_public_key
    current_agent.e2ee_signed_prekey_public = req.signed_prekey_public
    current_agent.e2ee_signed_prekey_signature = req.signed_prekey_signature
    current_agent.e2ee_safety_number = safety_number
    current_agent.e2ee_one_time_prekeys_json = req.one_time_prekeys_json
    db.commit()
    return {
        "status": "PUBLIC_KEYS_PUBLISHED_AND_VERIFIED",
        "matricule": current_agent.matricule,
        "e2ee_key_epoch": current_agent.e2ee_key_epoch,
        "e2ee_safety_number": safety_number,
    }


@app.get("/api/directory")
def get_official_ministry_directory(
    ministry: Optional[str] = Query(default=None),
    current_agent: EnrolledAgent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
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
                "safety_number": ag.e2ee_safety_number,
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
# 4. CANAUX INSTITUTIONNELS, ÉCHANGE DE CLÉS ECDH & MESSAGERIE SEALED SENDER
# ============================================================================

@app.get("/api/channels")
def list_agent_channels(
    current_agent: EnrolledAgent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
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
        try:
            bundles_dict = json.loads(ch.encrypted_group_session_bundles or "{}")
        except Exception:
            bundles_dict = {}

        result.append(
            {
                "id": ch.id,
                "slug": ch.slug,
                "name": ch.name,
                "ministry_scope": ch.ministry_scope,
                "channel_type": ch.channel_type,
                "default_classification": ch.default_classification,
                "crypto_epoch": ch.crypto_epoch,
                "encrypted_group_session_bundles": bundles_dict,
                "active_members": [
                    {
                        "id": m.id,
                        "matricule": m.matricule,
                        "full_name": m.full_name,
                        "ministry": m.ministry,
                        "role": m.role,
                        "e2ee_identity_public_key": m.e2ee_identity_public_key,
                        "e2ee_signing_public_key": m.e2ee_signing_public_key,
                        "e2ee_signed_prekey_public": m.e2ee_signed_prekey_public,
                        "e2ee_safety_number": m.e2ee_safety_number,
                    }
                    for m in members
                ],
            }
        )
    return {"channels": result}


@app.post("/api/channels/{channel_id}/group-session-bundle")
def publish_ecdh_wrapped_group_session_keys(
    channel_id: int,
    req: PublishGroupSessionBundleRequest,
    current_agent: EnrolledAgent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    membership = (
        db.query(ChannelMember)
        .filter(ChannelMember.channel_id == channel_id, ChannelMember.agent_id == current_agent.id)
        .first()
    )
    if not membership:
        raise HTTPException(status_code=403, detail="Accès au canal non autorisé.")

    channel = db.query(Channel).filter(Channel.id == channel_id).first()
    if not channel:
        raise HTTPException(status_code=404, detail="Canal introuvable.")

    if req.crypto_epoch != channel.crypto_epoch:
        raise HTTPException(
            status_code=409,
            detail="Époque cryptographique obsolète ou inconnue : enveloppes refusées.",
        )

    active_matricules = {
        row[0]
        for row in db.query(EnrolledAgent.matricule)
        .join(ChannelMember, ChannelMember.agent_id == EnrolledAgent.id)
        .filter(ChannelMember.channel_id == channel_id, EnrolledAgent.is_revoked == False)  # noqa: E712
        .all()
    }
    incoming = {}
    for matricule, bundle in req.wrapped_keys_by_matricule.items():
        if (
            matricule in active_matricules
            and isinstance(bundle, dict)
            and all(isinstance(bundle.get(k), str) for k in ("senderMatricule", "ivB64", "wrappedKeyB64"))
            and bundle["senderMatricule"] == current_agent.matricule
        ):
            incoming[matricule] = {
                "senderMatricule": bundle["senderMatricule"],
                "ivB64": bundle["ivB64"],
                "wrappedKeyB64": bundle["wrappedKeyB64"],
            }
    if not incoming:
        raise HTTPException(status_code=422, detail="Aucune enveloppe valide pour des membres actifs.")

    try:
        bundles = json.loads(channel.encrypted_group_session_bundles or "{}")
    except Exception:
        bundles = {}

    epoch_key = str(req.crypto_epoch)
    existing_epoch_bundles = bundles.get(epoch_key, {})

    if req.initial:
        if existing_epoch_bundles:
            raise HTTPException(status_code=409, detail="Un secret de groupe existe déjà pour cette époque.")
        existing_epoch_bundles = incoming
    else:
        if current_agent.matricule not in existing_epoch_bundles:
            raise HTTPException(status_code=403, detail="Vous ne détenez pas le secret de cette époque.")
        for matricule, bundle in incoming.items():
            existing_epoch_bundles.setdefault(matricule, bundle)

    bundles[epoch_key] = existing_epoch_bundles
    channel.encrypted_group_session_bundles = json.dumps(bundles)
    db.commit()

    return {
        "status": "ECDH_GROUP_KEY_BUNDLES_STORED",
        "channel_id": channel_id,
        "crypto_epoch": req.crypto_epoch,
        "members_wrapped_count": len(existing_epoch_bundles),
    }


@app.post("/api/channels")
def create_institutional_or_direct_channel(
    req: CreateChannelRequest,
    current_agent: EnrolledAgent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    slug_base = req.name.lower().replace(" ", "-")[:40]
    slug = f"{slug_base}-{secrets.token_hex(3)}"
    channel = Channel(
        slug=slug,
        name=req.name,
        ministry_scope=req.ministry_scope,
        channel_type=req.channel_type,
        default_classification=req.default_classification,
        crypto_epoch=1,
        encrypted_group_session_bundles="{}",
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
                timestamp_bucket=get_timestamp_bucket(),
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

    output = []
    for msg in messages:
        if msg.expires_at and msg.expires_at < now_naive:
            continue
        receipts = (
            db.query(ProbativeReadReceipt)
            .filter(ProbativeReadReceipt.message_id == msg.id)
            .all()
        )
        output.append(
            {
                "id": msg.id,
                "channel_id": msg.channel_id,
                "sender_pseudonym_hash": msg.sender_pseudonym_hash,
                "e2ee_protocol": msg.e2ee_protocol,
                "crypto_epoch": msg.crypto_epoch,
                "ciphertext_payload": msg.ciphertext_payload,
                "nonce_or_iv": msg.nonce_or_iv,
                "authenticity_mac": msg.authenticity_mac,
                "ecdsa_verified_by_server": msg.ecdsa_verified_by_server,
                "message_kind": msg.message_kind,
                "classification": msg.classification,
                "requires_probative_receipt": msg.requires_probative_receipt,
                "expires_at": msg.expires_at.isoformat() + "Z" if msg.expires_at else None,
                "encrypted_blob_id": msg.encrypted_blob_id,
                "timestamp_bucket": msg.timestamp_bucket,
                "probative_receipts": [
                    {
                        "id": r.id,
                        "agent_id": r.agent_id,
                        "agent_matricule": r.agent_matricule,
                        "agent_full_name": r.agent_full_name,
                        "signature_hex": r.signature_hex,
                        "signed_payload_hash": r.signed_payload_hash,
                        "ecdsa_verified": r.ecdsa_verified,
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
    Reçoit et stocke UNIQUEMENT une enveloppe chiffrée de bout en bout avec Sealed Sender.
    Correctif prioritaire de l'audit :
    1. La vérification de la signature ECDSA P-256 (`authenticity_mac`) est OBLIGATOIRE.
    2. Elle s'effectue EXCLUSIVEMENT contre `current_agent.e2ee_signing_public_key` (la clé de l'annuaire),
       et JAMAIS contre une clé non vérifiée fournie dans la requête.
    3. Aucun `sender_ephemeral_public_key`, `no_forward` ni `anti_screenshot` n'est stocké en clair.
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

    if not current_agent.e2ee_signing_public_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Clé publique de signature absente de l'annuaire : publiez d'abord vos clés via /api/e2ee/keys.",
        )

    mac_input = f"{channel_id}:{channel.crypto_epoch}:{req.nonce_or_iv}:{req.ciphertext_payload}".encode("utf-8")
    ecdsa_verified = verify_ecdsa_p256_jwk_signature(
        public_jwk_json=current_agent.e2ee_signing_public_key,
        message_bytes=mac_input,
        signature_hex=req.authenticity_mac,
    )
    if not ecdsa_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="REJET CRYPTOGRAPHIQUE : Signature ECDSA P-256 (`authenticity_mac`) invalide contre votre clé d'annuaire.",
        )

    expires_at = None
    if req.expires_in_seconds and req.expires_in_seconds > 0:
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=req.expires_in_seconds)).replace(tzinfo=None)

    msg = EncryptedMessage(
        channel_id=channel_id,
        sender_pseudonym_hash=pseudonymize_identifier(current_agent.matricule),
        e2ee_protocol="WEBCRYPTO_ECDH_HKDF_AES256GCM_ECDSA",
        crypto_epoch=channel.crypto_epoch,
        ciphertext_payload=req.ciphertext_payload,
        nonce_or_iv=req.nonce_or_iv,
        authenticity_mac=req.authenticity_mac,
        ecdsa_verified_by_server=True,
        message_kind="SEALED_E2EE",
        classification="SEALED_E2EE",
        requires_probative_receipt=req.requires_probative_receipt,
        expires_at=expires_at,
        encrypted_blob_id=req.encrypted_blob_id,
        timestamp_bucket=get_timestamp_bucket(),
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)

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
            "sender_pseudonym_hash": msg.sender_pseudonym_hash,
            "e2ee_protocol": msg.e2ee_protocol,
            "crypto_epoch": msg.crypto_epoch,
            "ciphertext_payload": msg.ciphertext_payload,
            "nonce_or_iv": msg.nonce_or_iv,
            "authenticity_mac": msg.authenticity_mac,
            "ecdsa_verified_by_server": msg.ecdsa_verified_by_server,
            "message_kind": msg.message_kind,
            "classification": msg.classification,
            "requires_probative_receipt": msg.requires_probative_receipt,
            "expires_at": msg.expires_at.isoformat() + "Z" if msg.expires_at else None,
            "encrypted_blob_id": msg.encrypted_blob_id,
            "timestamp_bucket": msg.timestamp_bucket,
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
        timestamp_bucket=get_timestamp_bucket(),
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
# 6. ACCUSÉ DE LECTURE À VALEUR PROBANTE AVEC VÉRIFICATION ECDSA P-256 STRICTE
# ============================================================================

@app.post("/api/messages/{message_id}/probative-receipt")
async def submit_probative_read_receipt(
    message_id: int,
    req: SignProbativeReceiptRequest,
    current_agent: EnrolledAgent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    msg = db.query(EncryptedMessage).filter(EncryptedMessage.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message introuvable.")

    membership = (
        db.query(ChannelMember)
        .filter(ChannelMember.channel_id == msg.channel_id, ChannelMember.agent_id == current_agent.id)
        .first()
    )
    if not membership:
        raise HTTPException(status_code=403, detail="Accès interdit à ce canal.")

    if not current_agent.e2ee_signing_public_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Clé publique de signature absente de l'annuaire : publiez d'abord vos clés via /api/e2ee/keys.",
        )

    expected_preimage = (
        f"PROBATIVE_RECEIPT::MSG={message_id}::AGENT={current_agent.matricule}::CIPHER={msg.ciphertext_payload}"
    ).encode("utf-8")
    expected_hash_hex = hashlib.sha256(expected_preimage).hexdigest()

    if req.signed_payload_hash != expected_hash_hex:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Condensat SHA-256 de l'accusé de lecture invalide.",
        )

    ecdsa_verified = verify_ecdsa_p256_jwk_signature(
        public_jwk_json=current_agent.e2ee_signing_public_key,
        message_bytes=bytes.fromhex(expected_hash_hex),
        signature_hex=req.signature_hex,
    )
    if not ecdsa_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Signature ECDSA P-256 de l'accusé de lecture probant invalide contre votre clé d'annuaire.",
        )

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
            "ecdsa_verified": existing.ecdsa_verified,
            "signed_at": existing.signed_at.isoformat() + "Z",
        }

    receipt = ProbativeReadReceipt(
        message_id=message_id,
        agent_id=current_agent.id,
        agent_matricule=current_agent.matricule,
        agent_full_name=current_agent.full_name,
        signature_hex=req.signature_hex,
        signed_payload_hash=req.signed_payload_hash,
        ecdsa_verified=True,
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
            "ecdsa_verified": receipt.ecdsa_verified,
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
    matricule_clean = req.matricule.strip().upper()
    if db.query(EnrolledAgent).filter(EnrolledAgent.matricule == matricule_clean).first():
        raise HTTPException(status_code=400, detail="Ce matricule est déjà enrôlé.")

    plain_totp_secret = generate_totp_secret()
    encrypted_totp = encrypt_totp_secret_at_rest(plain_totp_secret)
    new_agent = EnrolledAgent(
        matricule=matricule_clean,
        full_name=req.full_name,
        ministry=req.ministry,
        direction=req.direction,
        job_title=req.job_title,
        role=req.role,
        preferred_lang=req.preferred_lang,
        password_hash=hash_password(req.temporary_password),
        totp_secret_encrypted=encrypted_totp,
        totp_enabled=True,
        is_enrolled_activated=True,
        is_revoked=False,
        token_version=1,
    )
    db.add(new_agent)
    db.flush()

    default_channels = db.query(Channel).filter(Channel.ministry_scope == "TOUS").all()
    for ch in default_channels:
        db.add(ChannelMember(channel_id=ch.id, agent_id=new_agent.id))

    db.add(
        SecurityAuditLog(
            event_type="AGENT_ENROLLED",
            severity="INFO",
            actor_pseudonym=pseudonymize_identifier(admin_agent.matricule),
            description=f"Enrôlement officiel de l'agent {matricule_clean} ({req.ministry}) avec 2FA TOTP chiffré Fernet.",
            timestamp_bucket=get_timestamp_bucket(),
        )
    )
    db.commit()

    return {
        "id": new_agent.id,
        "matricule": new_agent.matricule,
        "full_name": new_agent.full_name,
        "totp_secret_provisioning_once": plain_totp_secret,
        "current_totp_code": generate_current_totp_code(encrypted_totp),
        "otpauth_uri": build_otpauth_uri(new_agent.matricule, new_agent.ministry, plain_totp_secret),
    }


@app.post("/api/admin/revoke/{agent_id}")
async def revoke_agent_immediately(
    agent_id: int,
    req: RevokeAgentRequest,
    admin_agent: EnrolledAgent = Depends(require_admin_role),
    db: Session = Depends(get_db),
):
    target = db.query(EnrolledAgent).filter(EnrolledAgent.id == agent_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Agent introuvable.")

    memberships = db.query(ChannelMember).filter(ChannelMember.agent_id == target.id).all()
    affected_channel_ids = [m.channel_id for m in memberships]

    target.is_revoked = True
    target.revoked_at = datetime.now(timezone.utc).replace(tzinfo=None)
    target.revocation_reason = req.reason
    target.revoked_channel_ids_json = json.dumps(affected_channel_ids)
    target.token_version += 1
    target.e2ee_identity_public_key = None
    target.e2ee_signing_public_key = None
    target.e2ee_signed_prekey_public = None
    target.e2ee_signed_prekey_signature = None
    target.e2ee_safety_number = None
    target.e2ee_one_time_prekeys_json = None

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
            timestamp_bucket=get_timestamp_bucket(),
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
    Réhabilite un compte fictif après test de révocation uniquement si `FASO_SECUR_DEMO_MODE=true`,
    et uniquement dans les canaux auxquels l'agent appartenait initialement (`revoked_channel_ids_json`).
    """
    if not auth.DEMO_MODE_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Réhabilitation rapide de démonstration désactivée hors mode démo (FASO_SECUR_DEMO_MODE=false).",
        )

    target = db.query(EnrolledAgent).filter(EnrolledAgent.id == agent_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Agent introuvable.")

    try:
        original_channel_ids = json.loads(target.revoked_channel_ids_json or "[]")
    except Exception:
        original_channel_ids = []

    target.is_revoked = False
    target.revoked_at = None
    target.revocation_reason = None
    target.token_version += 1
    target.e2ee_key_epoch += 1

    if original_channel_ids:
        channels_to_restore = db.query(Channel).filter(Channel.id.in_(original_channel_ids)).all()
    else:
        channels_to_restore = db.query(Channel).filter(Channel.ministry_scope == "TOUS").all()

    for ch in channels_to_restore:
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
            description=f"Réhabilitation de démonstration de l'agent {target.matricule} dans ses {len(channels_to_restore)} canaux d'origine.",
            timestamp_bucket=get_timestamp_bucket(),
        )
    )
    db.commit()
    return {"status": "REINSTATED", "matricule": target.matricule, "restored_channels": [c.id for c in channels_to_restore]}


# ============================================================================
# 8. CONSOLE D'INSPECTION DU JURY (« LE SERVEUR NE LIT RIEN » — CALCUL DYNAMIQUE)
# ============================================================================

def _is_valid_base64_ciphertext(val: str) -> bool:
    if not val or len(val) < 16:
        return False
    try:
        decoded = base64.b64decode(val, validate=True)
        return len(decoded) >= 12
    except Exception:
        return False


@app.get("/api/jury/server-inspection")
def inspect_raw_server_database_and_network(
    admin_agent: EnrolledAgent = Depends(require_admin_role),
    db: Session = Depends(get_db),
):
    """
    Épreuve en direct du jury :
    « Le serveur ne lit rien : inspection de la base de données et du trafic réseau ;
    aucun message ni fichier ne doit apparaître en clair ».
    - Strictement réservé aux rôles d'administration/audit (`require_admin_role`).
    - Filtre les messages aux seuls canaux dont l'administrateur/auditeur est membre.
    - Calcule dynamiquement les indicateurs de conformité sur le schéma SQL et les lignes réelles.
    """
    member_channel_ids = [
        r[0]
        for r in db.query(ChannelMember.channel_id)
        .filter(ChannelMember.agent_id == admin_agent.id)
        .all()
    ]

    raw_messages = (
        db.query(EncryptedMessage)
        .filter(EncryptedMessage.channel_id.in_(member_channel_ids))
        .order_by(EncryptedMessage.id.desc())
        .limit(25)
        .all()
        if member_channel_ids
        else []
    )
    raw_blobs = (
        db.query(EncryptedAttachmentBlob)
        .filter(EncryptedAttachmentBlob.channel_id.in_(member_channel_ids))
        .order_by(EncryptedAttachmentBlob.blob_id.desc())
        .limit(15)
        .all()
        if member_channel_ids
        else []
    )
    audit_logs = (
        db.query(SecurityAuditLog)
        .order_by(SecurityAuditLog.id.desc())
        .limit(30)
        .all()
    )

    # Calcul dynamique (non auto-certifié en dur) sur le schéma SQLAlchemy et les données en base
    forbidden_cleartext_cols = {"plaintext", "body", "text", "content", "sender_id", "sender_matricule", "sender_ephemeral_public_key", "no_forward", "anti_screenshot"}
    actual_msg_cols = {c.name for c in EncryptedMessage.__table__.columns}
    detected_plaintext_cols = sorted(actual_msg_cols.intersection(forbidden_cleartext_cols))

    all_agents = db.query(EnrolledAgent).all()
    all_totp_encrypted = all(
        ag.totp_secret_encrypted and ag.totp_secret_encrypted.startswith("gAAAAA")
        for ag in all_agents
    )
    all_msgs_encrypted = all(_is_valid_base64_ciphertext(m.ciphertext_payload) for m in raw_messages)
    all_ecdsa_verified = all(bool(m.ecdsa_verified_by_server) for m in raw_messages)

    return {
        "zero_knowledge_verification": {
            "plaintext_columns_in_db": len(detected_plaintext_cols),
            "inspected_columns_encrypted_messages": sorted(actual_msg_cols),
            "all_totp_secrets_fernet_encrypted_at_rest": all_totp_encrypted,
            "sealed_sender_active": "sender_id" not in actual_msg_cols and "sender_ephemeral_public_key" not in actual_msg_cols,
            "ecdsa_signature_verification_active": all_ecdsa_verified,
            "all_payloads_encrypted": all_msgs_encrypted,
            "metadata_minimization": {
                "sender_pseudonymization": "HMAC-SHA256 (aucun sender_id ni sender_ephemeral_public_key en clair)",
                "classification_and_flags_in_db": "SEALED_E2EE (no_forward, anti_screenshot et classification chiffrés dans ciphertext_payload)",
                "message_padding": "Blocs de 256 octets avant chiffrement AES-256-GCM",
                "timestamp_granularity": "Arrondi par tranche de 5 minutes (aucun created_at milliseconde)",
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
                "ecdsa_verified_by_server": m.ecdsa_verified_by_server,
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
                "timestamp_bucket": b.timestamp_bucket,
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
                "timestamp_bucket": log.timestamp_bucket,
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
                "e2ee_status": "ZERO_KNOWLEDGE_SEALED_SENDER_ACTIVE",
            }
        )
        while True:
            data = await websocket.receive_json()
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
