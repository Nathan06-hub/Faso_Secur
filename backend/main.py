"""
Serveur Souverain Zero-Knowledge & Sealed Sender FASO-SÉCUR — API FastAPI & WebSockets Temps Réel.
Développé pour le Sprint Technique Pré-Hackathon 226 (MTDPCE / DGTD — Burkina Faso).
"""

import base64
import hashlib
import json
import os
import secrets
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Response, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import inspect, text
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
    prekey_reservation_rate_limiter,
    pseudonymize_identifier,
    require_account_manager,
    require_admin_role,
    require_super_admin,
    verify_and_load_active_agent,
    verify_ecdsa_p256_jwk_signature,
    verify_password,
    verify_totp_code,
    websocket_ticket_rate_limiter,
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
    WebSocketTicket,
)
from provisioning import generate_activation_code, hash_activation_code
from seed import DEMO_AGENTS, seed_demo_data, seed_institutional_channels
from ws_manager import ws_manager


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    # `create_all` ne modifie pas les tables existantes ; migrer cette colonne sans
    # imposer un changement aux comptes déjà actifs.
    if "enrolled_agents" in inspect(engine).get_table_names():
        columns = {column["name"] for column in inspect(engine).get_columns("enrolled_agents")}
        if "must_change_password" not in columns:
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "ALTER TABLE enrolled_agents ADD COLUMN "
                        "must_change_password BOOLEAN NOT NULL DEFAULT FALSE"
                    )
                )
        if "enrolment_token_expires_at" not in columns:
            with engine.begin() as connection:
                connection.execute(
                    text("ALTER TABLE enrolled_agents ADD COLUMN enrolment_token_expires_at DATETIME NULL")
                )
    db = SessionLocal()
    try:
        seed_institutional_channels(db)
        if auth.DEMO_MODE_ENABLED:
            seed_demo_data(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title="FASO-SÉCUR — Serveur Souverain Zero-Knowledge (MTDPCE / DGTD)",
    description=(
        "Messagerie instantanée souveraine de l'administration publique du Burkina Faso. "
        "Chiffrement de bout en bout via le protocole Signal (@privacyresearch/libsignal-protocol-typescript : "
        "X3DH + Double Ratchet + AES-256-GCM + signatures ECDSA P-256), "
        "Authentification Forte 2FA TOTP (RFC 6238 chiffré Fernet), Révocation Immédiate."
    ),
    version="1.3.0",
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


class FirstPasswordChangeRequest(BaseModel):
    new_password: str = Field(..., min_length=12, max_length=72)


class AccountActivationStartRequest(BaseModel):
    matricule: str = Field(..., min_length=3, max_length=64)
    activation_code: str = Field(..., min_length=32, max_length=128)


class AccountActivationCompleteRequest(BaseModel):
    new_password: str = Field(..., min_length=12, max_length=72)
    totp_code: str = Field(..., min_length=6, max_length=6)


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


class ReplenishPreKeysRequest(BaseModel):
    new_one_time_prekeys: List[Dict[str, Any]] = Field(..., min_length=1)
    signature_hex: str = Field(
        ...,
        min_length=16,
        description="Signature ECDSA P-256 du lot de réapprovisionnement de pré-clés Signal",
    )


_PREKEY_RESERVATION_LOCK = threading.Lock()


class PublishGroupSessionBundleRequest(BaseModel):
    crypto_epoch: int
    wrapped_keys_by_matricule: Dict[str, Any]
    initial: bool = False


SUPPORTED_E2EE_PROTOCOL = "SIGNAL_X3DH_DOUBLERATCHET_AES256GCM_ECDSA"


class SendEncryptedMessageRequest(BaseModel):
    e2ee_protocol: str = Field(default=SUPPORTED_E2EE_PROTOCOL)
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
    role: Literal["AGENT_PUBLIC", "AUDITEUR", "POINT_FOCAL", "SUPER_ADMIN_DGTD"] = "AGENT_PUBLIC"
    preferred_lang: str = "fr"


class RevokeAgentRequest(BaseModel):
    reason: str = "Fin de mission / Perte d'appareil signalée à la DGTD"


class ChangeAgentRoleRequest(BaseModel):
    role: Literal["AGENT_PUBLIC", "AUDITEUR", "POINT_FOCAL", "SUPER_ADMIN_DGTD"]


class CreateChannelRequest(BaseModel):
    name: str
    ministry_scope: str = "TOUS"
    channel_type: str = "GROUP"
    default_classification: str = "DIFFUSION_RESTREINTE"
    member_ids: List[int] = []


def _record_audit_event(
    db: Session,
    actor: EnrolledAgent,
    event_type: str,
    description: str,
    severity: str = "INFO",
) -> None:
    """Add a privacy-minimized audit event; never pass message or file contents here."""
    db.add(
        SecurityAuditLog(
            event_type=event_type,
            severity=severity,
            actor_pseudonym=pseudonymize_identifier(actor.matricule),
            description=description,
            timestamp_bucket=get_timestamp_bucket(),
        )
    )


def _same_ministry(first: str, second: str) -> bool:
    return (first or "").strip().casefold() == (second or "").strip().casefold()


def _ministry_scope_matches(scope: str, ministry: str) -> bool:
    normalized_scope = (scope or "").strip().casefold()
    normalized_ministry = (ministry or "").strip().casefold()
    if not normalized_scope or normalized_scope == "tous":
        return False
    return (
        normalized_scope == normalized_ministry
        or normalized_ministry.startswith(normalized_scope + " /")
        or normalized_scope.startswith(normalized_ministry + " /")
    )


# ============================================================================
# 1. SANTÉ & COMPTES DE DÉMONSTRATION FICTIFS (CONTRÔLÉS PAR DEMO_MODE)
# ============================================================================

@app.get("/api/health")
def health_check():
    return {
        "status": "OPERATIONAL",
        "sovereign_hosting": True,
        "external_dependencies": "NONE (Zero Third-Party Services)",
        "e2ee_enforcement": f"{SUPPORTED_E2EE_PROTOCOL}_SEALED_SENDER",
        "two_factor_auth": "RFC_6238_TOTP_FERNET_ENCRYPTED_AT_REST",
        "demo_mode": auth.DEMO_MODE_ENABLED,
    }


@app.get("/api/auth/demo-accounts")
def list_fictional_demo_accounts(db: Session = Depends(get_db)):
    """
    Retourne la liste des profils fictifs de démonstration UNIQUEMENT lorsque
    `FASO_SECUR_DEMO_MODE=true`.
    Conformément à l'audit de sécurité :
    1. Isolé aux seuls comptes marqués `is_demo_account == True` (n'expose jamais les comptes réels enrôlés).
    2. Cet endpoint public ne divulgue JAMAIS de mot de passe (`demo_password`), ni de code TOTP
       (`current_totp_code`), ni de graine TOTP (`totp_secret`).
    """
    if not auth.DEMO_MODE_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Endpoint de démonstration désactivé hors mode démo (FASO_SECUR_DEMO_MODE=false).",
        )

    demo_matricules = {item["matricule"] for item in DEMO_AGENTS}
    agents = (
        db.query(EnrolledAgent)
        .filter(
            EnrolledAgent.is_demo_account == True,  # noqa: E712
            EnrolledAgent.matricule.in_(demo_matricules),
        )
        .order_by(EnrolledAgent.id.asc())
        .all()
    )
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
                "is_demo_account": True,
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

    if agent.is_demo_account and not auth.DEMO_MODE_ENABLED:
        login_rate_limiter.record_failure(matricule_clean)
        db.add(
            SecurityAuditLog(
                event_type="DEMO_ACCOUNT_LOGIN_BLOCKED",
                severity="WARNING",
                actor_pseudonym=pseudonymize_identifier(agent.matricule),
                description="Compte de démonstration bloqué hors mode démo.",
                timestamp_bucket=get_timestamp_bucket(),
            )
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Compte de démonstration désactivé hors mode démo.",
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
    if agent.must_change_password:
        now = datetime.now(timezone.utc)
        change_secret = hashlib.sha256(
            f"{auth.JWT_SECRET_KEY}:first-password-change".encode("utf-8")
        ).hexdigest()
        change_token = auth.jwt.encode(
            {
                "sub": agent.matricule,
                "agent_id": agent.id,
                "token_version": agent.token_version,
                "purpose": "first_password_change",
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(minutes=15)).timestamp()),
            },
            change_secret,
            algorithm=auth.JWT_ALGORITHM,
        )
        db.add(
            SecurityAuditLog(
                event_type="FIRST_LOGIN_PASSWORD_CHANGE_REQUIRED",
                severity="INFO",
                actor_pseudonym=pseudonymize_identifier(agent.matricule),
                description="Authentification forte validée ; accès limité au changement du mot de passe initial.",
                timestamp_bucket=get_timestamp_bucket(),
            )
        )
        db.commit()
        return {
            "password_change_required": True,
            "password_change_token": change_token,
            "agent": {
                "id": agent.id,
                "matricule": agent.matricule,
                "full_name": agent.full_name,
                "ministry": agent.ministry,
                "preferred_lang": agent.preferred_lang,
            },
        }

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


@app.post("/api/auth/first-password-change")
def change_initial_password(
    req: FirstPasswordChangeRequest,
    credentials=Depends(auth.security_bearer),
    db: Session = Depends(get_db),
):
    """Échange le jeton restreint du premier accès contre une session normale."""
    if not credentials or not credentials.credentials:
        raise HTTPException(status_code=401, detail="Authentification requise.")

    change_secret = hashlib.sha256(
        f"{auth.JWT_SECRET_KEY}:first-password-change".encode("utf-8")
    ).hexdigest()
    try:
        payload = auth.jwt.decode(
            credentials.credentials,
            change_secret,
            algorithms=[auth.JWT_ALGORITHM],
        )
    except auth.jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Session de changement invalide ou expirée.") from exc

    if payload.get("purpose") != "first_password_change":
        raise HTTPException(status_code=401, detail="Cette session ne permet pas cette opération.")

    matricule = payload.get("sub")
    agent = db.query(EnrolledAgent).filter(EnrolledAgent.matricule == matricule).first()
    if (
        not agent
        or not agent.is_enrolled_activated
        or agent.is_revoked
        or not agent.must_change_password
        or agent.id != payload.get("agent_id")
        or agent.token_version != payload.get("token_version")
    ):
        raise HTTPException(status_code=401, detail="Ce changement de mot de passe n'est plus autorisé.")

    rate_limit_key = f"first-password-change:{agent.matricule}"
    login_rate_limiter.check_allowed(rate_limit_key)
    password = req.new_password
    if len(password.encode("utf-8")) > 72:
        login_rate_limiter.record_failure(rate_limit_key)
        raise HTTPException(status_code=422, detail="Le mot de passe ne doit pas dépasser 72 octets.")
    if not (any(char.islower() for char in password) and any(char.isupper() for char in password) and any(char.isdigit() for char in password)):
        login_rate_limiter.record_failure(rate_limit_key)
        raise HTTPException(
            status_code=422,
            detail="Utilisez au moins 12 caractères, avec une majuscule, une minuscule et un chiffre.",
        )
    if verify_password(password, agent.password_hash):
        login_rate_limiter.record_failure(rate_limit_key)
        raise HTTPException(status_code=422, detail="Choisissez un mot de passe différent du mot de passe temporaire.")

    agent.password_hash = hash_password(password)
    agent.must_change_password = False
    agent.token_version += 1
    db.add(
        SecurityAuditLog(
            event_type="INITIAL_PASSWORD_CHANGED",
            severity="INFO",
            actor_pseudonym=pseudonymize_identifier(agent.matricule),
            description="Mot de passe initial remplacé avec succès ; les sessions précédentes ont été invalidées.",
            timestamp_bucket=get_timestamp_bucket(),
        )
    )
    db.commit()
    login_rate_limiter.reset(rate_limit_key)

    return {
        "access_token": create_access_token(agent),
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


def _account_activation_token_secret() -> str:
    return hashlib.sha256(f"{auth.JWT_SECRET_KEY}:account-activation".encode("utf-8")).hexdigest()


@app.post("/api/auth/activation/start")
def start_account_activation(
    req: AccountActivationStartRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    """Consume an invitation once and provision the agent's TOTP seed directly to their browser."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    matricule = req.matricule.strip().upper()
    rate_key = f"activation-start:{matricule}"
    login_rate_limiter.check_allowed(rate_key)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    plain_totp_secret = generate_totp_secret()
    encrypted_totp = encrypt_totp_secret_at_rest(plain_totp_secret)

    claimed = (
        db.query(EnrolledAgent)
        .filter(
            EnrolledAgent.matricule == matricule,
            EnrolledAgent.is_enrolled_activated == False,  # noqa: E712
            EnrolledAgent.is_revoked == False,  # noqa: E712
            EnrolledAgent.enrolment_token == hash_activation_code(req.activation_code),
            EnrolledAgent.enrolment_token_expires_at > now,
        )
        .update(
            {
                EnrolledAgent.enrolment_token: None,
                EnrolledAgent.enrolment_token_expires_at: None,
                EnrolledAgent.totp_secret_encrypted: encrypted_totp,
                EnrolledAgent.totp_enabled: False,
                EnrolledAgent.token_version: EnrolledAgent.token_version + 1,
            },
            synchronize_session=False,
        )
    )
    if claimed != 1:
        login_rate_limiter.record_failure(rate_key)
        db.add(
            SecurityAuditLog(
                event_type="ACCOUNT_ACTIVATION_REJECTED",
                severity="WARNING",
                actor_pseudonym=pseudonymize_identifier(matricule),
                description="Code d'activation invalide, expiré ou déjà consommé.",
                timestamp_bucket=get_timestamp_bucket(),
            )
        )
        db.commit()
        raise HTTPException(status_code=403, detail="Code d'activation invalide, expiré ou déjà utilisé.")

    db.expire_all()
    agent = db.query(EnrolledAgent).filter(EnrolledAgent.matricule == matricule).one()
    login_rate_limiter.reset(rate_key)
    now_aware = datetime.now(timezone.utc)
    activation_token = auth.jwt.encode(
        {
            "sub": agent.matricule,
            "agent_id": agent.id,
            "token_version": agent.token_version,
            "purpose": "account_activation",
            "iat": int(now_aware.timestamp()),
            "exp": int((now_aware + timedelta(minutes=15)).timestamp()),
        },
        _account_activation_token_secret(),
        algorithm=auth.JWT_ALGORITHM,
    )
    db.add(
        SecurityAuditLog(
            event_type="ACCOUNT_ACTIVATION_STARTED",
            severity="INFO",
            actor_pseudonym=pseudonymize_identifier(agent.matricule),
            description="Code d'invitation consommé; configuration TOTP en cours par l'agent.",
            timestamp_bucket=get_timestamp_bucket(),
        )
    )
    db.commit()
    return {
        "activation_token": activation_token,
        "totp_secret": plain_totp_secret,
        "otpauth_uri": build_otpauth_uri(agent.matricule, agent.ministry, plain_totp_secret),
        "expires_in_seconds": 900,
        "agent": {
            "matricule": agent.matricule,
            "full_name": agent.full_name,
            "ministry": agent.ministry,
        },
    }


@app.post("/api/auth/activation/complete")
def complete_account_activation(
    req: AccountActivationCompleteRequest,
    response: Response,
    credentials=Depends(auth.security_bearer),
    db: Session = Depends(get_db),
):
    """Activate the account only after the agent proves possession of their new TOTP seed."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    if not credentials or not credentials.credentials:
        raise HTTPException(status_code=401, detail="Session d'activation requise.")
    try:
        payload = auth.jwt.decode(
            credentials.credentials,
            _account_activation_token_secret(),
            algorithms=[auth.JWT_ALGORITHM],
        )
    except auth.jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Session d'activation invalide ou expirée.") from exc
    if payload.get("purpose") != "account_activation":
        raise HTTPException(status_code=401, detail="Cette session ne permet pas l'activation du compte.")

    agent = db.query(EnrolledAgent).filter(EnrolledAgent.matricule == payload.get("sub")).first()
    if (
        not agent
        or agent.id != payload.get("agent_id")
        or agent.is_enrolled_activated
        or agent.is_revoked
        or agent.token_version != payload.get("token_version")
    ):
        raise HTTPException(status_code=401, detail="Cette activation n'est plus valide.")

    rate_key = f"activation-complete:{agent.matricule}"
    login_rate_limiter.check_allowed(rate_key)
    password = req.new_password
    if len(password.encode("utf-8")) > 72 or not (
        len(password) >= 12
        and any(char.islower() for char in password)
        and any(char.isupper() for char in password)
        and any(char.isdigit() for char in password)
    ):
        login_rate_limiter.record_failure(rate_key)
        raise HTTPException(
            status_code=422,
            detail="Utilisez un mot de passe de 12 à 72 octets avec une majuscule, une minuscule et un chiffre.",
        )
    if not verify_totp_code(agent.totp_secret_encrypted, req.totp_code):
        login_rate_limiter.record_failure(rate_key)
        db.add(
            SecurityAuditLog(
                event_type="ACCOUNT_ACTIVATION_TOTP_FAILED",
                severity="WARNING",
                actor_pseudonym=pseudonymize_identifier(agent.matricule),
                description="Preuve de possession TOTP invalide pendant l'activation.",
                timestamp_bucket=get_timestamp_bucket(),
            )
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Code de l'application d'authentification invalide.")

    agent.password_hash = hash_password(password)
    agent.must_change_password = False
    agent.totp_enabled = True
    agent.is_enrolled_activated = True
    agent.token_version += 1
    db.add(
        SecurityAuditLog(
            event_type="ACCOUNT_ACTIVATED",
            severity="INFO",
            actor_pseudonym=pseudonymize_identifier(agent.matricule),
            description="Agent activé après choix de son mot de passe et validation de son second facteur TOTP.",
            timestamp_bucket=get_timestamp_bucket(),
        )
    )
    db.commit()
    login_rate_limiter.reset(rate_key)
    return {
        "access_token": create_access_token(agent),
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


@app.post("/api/auth/ws-ticket")
def create_websocket_ticket(
    response: Response,
    current_agent: EnrolledAgent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    """Émet un ticket opaque, bref et à usage unique pour l'authentification WebSocket."""
    # Les colonnes SQLAlchemy DateTime utilisent des valeurs UTC sans tzinfo
    # pour rester comparables sur SQLite comme sur PostgreSQL.
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    websocket_ticket_rate_limiter.check_and_record(current_agent.id)
    expires_at = now + timedelta(seconds=30)
    db.query(WebSocketTicket).filter(WebSocketTicket.expires_at <= now).delete(
        synchronize_session=False
    )

    ticket = secrets.token_urlsafe(32)
    db.add(
        WebSocketTicket(
            ticket_hash=hashlib.sha256(ticket.encode("utf-8")).hexdigest(),
            agent_id=current_agent.id,
            token_version=current_agent.token_version,
            expires_at=expires_at,
        )
    )
    db.commit()
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return {"ticket": ticket, "expires_in": 30}


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

def _sanitize_public_prekey_bundle_for_directory(raw_json_str: Optional[str]) -> Optional[str]:
    """
    Filtre le bundle Signal X3DH pour l'annuaire (`/api/directory`) et la liste des
    membres de canaux (`/api/channels`).
    Ne publie JAMAIS la liste complète `oneTimePreKeys` ni de pré-clé à usage unique
    `preKey` en vrac : seuls les éléments publics d'identité et de SignedPreKey ainsi
    que le compteur de disponibilité (`available_one_time_prekeys_count`) sont exposés.
    La délivrance d'une One-Time PreKey s'effectue exclusivement à l'unité via
    `POST /api/e2ee/prekeys/consume/{target_matricule}`.
    """
    if not raw_json_str:
        return raw_json_str
    try:
        parsed = json.loads(raw_json_str)
        if not isinstance(parsed, dict):
            return raw_json_str
        sig_bundle = parsed.get("signal_prekey_bundle")
        if not isinstance(sig_bundle, dict):
            return raw_json_str
        otpk_list = sig_bundle.get("oneTimePreKeys")
        consumed_ids = set(sig_bundle.get("consumedPreKeyIds") or [])
        available_count = (
            len([pk for pk in otpk_list if isinstance(pk, dict) and pk.get("keyId") not in consumed_ids])
            if isinstance(otpk_list, list)
            else 0
        )
        sanitized = {
            "protocol": parsed.get("protocol", SUPPORTED_E2EE_PROTOCOL),
            "signal_prekey_bundle": {
                "registrationId": sig_bundle.get("registrationId", 1),
                "identityKeyB64": sig_bundle.get("identityKeyB64"),
                "signedPreKey": sig_bundle.get("signedPreKey"),
                "available_one_time_prekeys_count": available_count,
                "prekeys_exhausted": available_count == 0,
            },
        }
        return json.dumps(sanitized, separators=(",", ":"))
    except Exception:
        return None


def _merge_published_prekeys_preserving_consumed(
    existing_raw_json: Optional[str],
    incoming_raw_json: str,
) -> tuple[str, int, List[int]]:
    """
    Lorsqu'un agent republie son trousseau public au rechargement du navigateur,
    préserve strictement l'ensemble `consumedPreKeyIds` déjà enregistré sur le serveur
    pour la même clé d'identité Signal (`identityKeyB64`), afin qu'aucune One-Time PreKey
    déjà réservée/consommée ne puisse réapparaître.
    """
    try:
        incoming = json.loads(incoming_raw_json)
    except Exception:
        return incoming_raw_json, 0, []

    if not isinstance(incoming, dict) or not isinstance(incoming.get("signal_prekey_bundle"), dict):
        return incoming_raw_json, 0, []

    inc_bundle = incoming["signal_prekey_bundle"]
    inc_identity = inc_bundle.get("identityKeyB64")
    consumed_ids: List[int] = [
        int(k)
        for k in (inc_bundle.get("consumedPreKeyIds") or [])
        if isinstance(k, (int, str)) and str(k).isdigit()
    ]

    if existing_raw_json:
        try:
            existing = json.loads(existing_raw_json)
            ex_bundle = existing.get("signal_prekey_bundle") if isinstance(existing, dict) else None
            if isinstance(ex_bundle, dict) and ex_bundle.get("identityKeyB64") == inc_identity:
                for cid in ex_bundle.get("consumedPreKeyIds") or []:
                    if isinstance(cid, (int, str)) and str(cid).isdigit():
                        cid_int = int(cid)
                        if cid_int not in consumed_ids:
                            consumed_ids.append(cid_int)
        except Exception:
            pass

    consumed_set = set(consumed_ids)
    raw_otpk = inc_bundle.get("oneTimePreKeys")
    filtered_otpk: List[Dict[str, Any]] = []
    seen_ids = set()
    if isinstance(raw_otpk, list):
        for pk in raw_otpk:
            if not isinstance(pk, dict):
                continue
            kid = pk.get("keyId")
            if isinstance(kid, (int, str)) and str(kid).isdigit():
                kid_int = int(kid)
                if kid_int in consumed_set or kid_int in seen_ids:
                    continue
                seen_ids.add(kid_int)
                filtered_otpk.append({"keyId": kid_int, "publicKeyB64": pk.get("publicKeyB64")})

    inc_bundle["oneTimePreKeys"] = filtered_otpk
    inc_bundle["preKey"] = filtered_otpk[0] if filtered_otpk else None
    inc_bundle["consumedPreKeyIds"] = consumed_ids
    return json.dumps(incoming, separators=(",", ":")), len(filtered_otpk), consumed_ids


@app.post("/api/e2ee/keys")
def publish_agent_public_key_bundle(
    req: PublishPublicKeysRequest,
    current_agent: EnrolledAgent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    """
    Enregistre uniquement les clés PUBLIQUES E2EE de l'agent (IdentityKey ECDH, SigningKey ECDSA, SignedPreKey)
    et le stock de pré-clés publiques Signal à usage unique, en préservant strictement les IDs de pré-clés
    déjà consommés (`consumedPreKeyIds`) pour empêcher toute réapparition après rechargement.
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

    with _PREKEY_RESERVATION_LOCK:
        merged_json, remaining_count, consumed_ids = _merge_published_prekeys_preserving_consumed(
            current_agent.e2ee_one_time_prekeys_json,
            req.one_time_prekeys_json,
        )
        current_agent.e2ee_identity_public_key = req.identity_public_key
        current_agent.e2ee_signing_public_key = req.signing_public_key
        current_agent.e2ee_signed_prekey_public = req.signed_prekey_public
        current_agent.e2ee_signed_prekey_signature = req.signed_prekey_signature
        current_agent.e2ee_safety_number = safety_number
        current_agent.e2ee_one_time_prekeys_json = merged_json
        db.commit()

    return {
        "status": "PUBLIC_KEYS_PUBLISHED_AND_VERIFIED",
        "matricule": current_agent.matricule,
        "e2ee_key_epoch": current_agent.e2ee_key_epoch,
        "e2ee_safety_number": safety_number,
        "remaining_one_time_prekeys": remaining_count,
        "consumed_prekey_ids": consumed_ids,
        "replenishment_required": remaining_count <= 5,
    }


@app.post("/api/e2ee/prekeys/consume/{target_matricule}")
def consume_one_time_prekey_bundle(
    target_matricule: str,
    channel_id: Optional[int] = None,
    current_agent: EnrolledAgent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    """
    Réserve et consomme atomiquement une pré-clé à usage unique (One-Time PreKey X3DH)
    pour établir une nouvelle session Signal vers `target_matricule`.
    Contrôles appliqués :
    1. L'émetteur et le destinataire doivent tous deux être actifs (`is_revoked == False`)
       et partager au moins un canal actif où l'émetteur est membre (ou `channel_id` s'il est précisé).
    2. Limitation de débit (`prekey_reservation_rate_limiter`) et journal d'audit contre l'épuisement volontaire.
    3. Réservation atomique compatible SQLite et PostgreSQL (verrou + mise à jour conditionnelle CAS)
       garantissant que deux requêtes simultanées ne reçoivent jamais la même pré-clé.
    4. En cas d'épuisement du stock (`remaining_one_time_prekeys == 0`), retourne `preKey: null`
       (`prekeys_exhausted: True, replenishment_required: True`) pour permettre l'initiation X3DH
       conforme au protocole Signal via la `signedPreKey` sans jamais réutiliser une pré-clé consommée.
    """
    target_clean = target_matricule.strip().upper()
    target_initial = (
        db.query(EnrolledAgent)
        .filter(
            EnrolledAgent.matricule == target_clean,
            EnrolledAgent.is_enrolled_activated == True,  # noqa: E712
            EnrolledAgent.is_revoked == False,  # noqa: E712
        )
        .first()
    )
    if not target_initial or not target_initial.e2ee_one_time_prekeys_json:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent cible actif ou bundle Signal X3DH introuvable.",
        )

    # 1. Vérification d'appartenance à un canal partagé où l'émetteur est membre actif
    sender_channel_ids = {
        row[0]
        for row in db.query(ChannelMember.channel_id)
        .filter(ChannelMember.agent_id == current_agent.id)
        .all()
    }
    target_channel_ids = {
        row[0]
        for row in db.query(ChannelMember.channel_id)
        .filter(ChannelMember.agent_id == target_initial.id)
        .all()
    }

    resolved_channel_id = channel_id if isinstance(channel_id, int) else None
    if resolved_channel_id is not None:
        shares_authorized_channel = (
            resolved_channel_id in sender_channel_ids
            and (resolved_channel_id in target_channel_ids or current_agent.id == target_initial.id)
        )
    else:
        shares_authorized_channel = (
            bool(sender_channel_ids.intersection(target_channel_ids))
            or current_agent.id == target_initial.id
        )

    if not shares_authorized_channel:
        db.add(
            SecurityAuditLog(
                event_type="PREKEY_RESERVATION_DENIED",
                severity="WARNING",
                actor_pseudonym=pseudonymize_identifier(current_agent.matricule),
                description=(
                    f"Réservation de pré-clé Signal refusée : {current_agent.matricule} "
                    f"ne partage aucun canal autorisé avec {target_initial.matricule}."
                ),
                timestamp_bucket=get_timestamp_bucket(),
            )
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Réservation de pré-clé Signal refusée : l'émetteur et le destinataire "
                "doivent être actifs et partager un canal où l'émetteur est membre."
            ),
        )

    # 2. Limitation de débit contre l'épuisement volontaire des pré-clés
    try:
        prekey_reservation_rate_limiter.check_and_record(current_agent.matricule, target_clean)
    except HTTPException as rate_exc:
        db.add(
            SecurityAuditLog(
                event_type="PREKEY_EXHAUSTION_RATE_LIMITED",
                severity="WARNING",
                actor_pseudonym=pseudonymize_identifier(current_agent.matricule),
                description=(
                    f"Limitation de débit déclenchée sur la réservation de pré-clés Signal "
                    f"par {current_agent.matricule} vers {target_clean}."
                ),
                timestamp_bucket=get_timestamp_bucket(),
            )
        )
        db.commit()
        raise rate_exc

    # 3. Réservation atomique (compatible SQLite & PostgreSQL)
    with _PREKEY_RESERVATION_LOCK:
        consumed_prekey: Optional[Dict[str, Any]] = None
        remaining_count = 0
        sig_bundle: Optional[Dict[str, Any]] = None

        for _attempt in range(5):
            db.expire_all()
            query = db.query(EnrolledAgent).filter(
                EnrolledAgent.id == target_initial.id,
                EnrolledAgent.is_revoked == False,  # noqa: E712
            )
            if db.bind is not None and getattr(db.bind.dialect, "name", "") == "postgresql":
                query = query.with_for_update()

            target = query.first()
            if not target or not target.e2ee_one_time_prekeys_json:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Agent cible ou bundle Signal X3DH introuvable.",
                )

            old_raw_json = target.e2ee_one_time_prekeys_json
            try:
                parsed = json.loads(old_raw_json)
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Format JSON du bundle Signal X3DH invalide.",
                ) from exc

            sig_bundle = parsed.get("signal_prekey_bundle") if isinstance(parsed, dict) else None
            if not isinstance(sig_bundle, dict):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Bundle Signal X3DH absent pour cet agent.",
                )

            consumed_ids: List[int] = [
                int(k)
                for k in (sig_bundle.get("consumedPreKeyIds") or [])
                if isinstance(k, (int, str)) and str(k).isdigit()
            ]
            consumed_set = set(consumed_ids)

            raw_otpk = sig_bundle.get("oneTimePreKeys")
            otpk_list: List[Dict[str, Any]] = [
                pk
                for pk in (raw_otpk if isinstance(raw_otpk, list) else [])
                if isinstance(pk, dict) and pk.get("keyId") not in consumed_set
            ]

            consumed_prekey = None
            if len(otpk_list) > 0:
                consumed_prekey = otpk_list.pop(0)
                kid = consumed_prekey.get("keyId")
                if isinstance(kid, (int, str)) and str(kid).isdigit():
                    kid_int = int(kid)
                    if kid_int not in consumed_set:
                        consumed_ids.append(kid_int)

            sig_bundle["oneTimePreKeys"] = otpk_list
            sig_bundle["preKey"] = otpk_list[0] if len(otpk_list) > 0 else None
            sig_bundle["consumedPreKeyIds"] = consumed_ids
            remaining_count = len(otpk_list)
            new_raw_json = json.dumps(parsed, separators=(",", ":"))

            updated_rows = (
                db.query(EnrolledAgent)
                .filter(
                    EnrolledAgent.id == target.id,
                    EnrolledAgent.e2ee_one_time_prekeys_json == old_raw_json,
                )
                .update(
                    {"e2ee_one_time_prekeys_json": new_raw_json},
                    synchronize_session=False,
                )
            )
            if updated_rows == 1:
                db.add(
                    SecurityAuditLog(
                        event_type=(
                            "PREKEY_CONSUMED_X3DH"
                            if consumed_prekey is not None
                            else "PREKEY_EXHAUSTED_SIGNED_PREKEY_FALLBACK"
                        ),
                        severity="INFO" if consumed_prekey is not None else "WARNING",
                        actor_pseudonym=pseudonymize_identifier(current_agent.matricule),
                        description=(
                            f"Pré-clé Signal X3DH réservée et consommée (keyId={consumed_prekey.get('keyId')}) "
                            f"pour session vers {target.matricule} (restantes={remaining_count})."
                            if consumed_prekey is not None
                            else f"Aucune One-Time PreKey restante pour {target.matricule} ; "
                            "initiation X3DH conforme Signal via SignedPreKey uniquement (sans réutilisation)."
                        ),
                        timestamp_bucket=get_timestamp_bucket(),
                    )
                )
                db.commit()
                break
        else:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Conflit d'accès concurrent lors de la réservation de pré-clé Signal ; veuillez réessayer.",
            )

    return {
        "matricule": target_initial.matricule,
        "protocol": SUPPORTED_E2EE_PROTOCOL,
        "consumed_prekey": consumed_prekey,
        "remaining_one_time_prekeys": remaining_count,
        "prekeys_exhausted": consumed_prekey is None,
        "replenishment_required": remaining_count <= 5,
        "signal_prekey_bundle": {
            "registrationId": sig_bundle.get("registrationId", 1),
            "identityKeyB64": sig_bundle.get("identityKeyB64"),
            "signedPreKey": sig_bundle.get("signedPreKey"),
            "preKey": consumed_prekey,
        },
    }


@app.post("/api/e2ee/prekeys/replenish")
def replenish_one_time_prekeys(
    req: ReplenishPreKeysRequest,
    current_agent: EnrolledAgent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    """
    Réapprovisionne de manière authentifiée (JWT + signature ECDSA P-256 vérifiée contre l'annuaire)
    le stock de pré-clés publiques Signal à usage unique (`oneTimePreKeys`) de l'agent.
    Rejette catégoriquement toute pré-clé dont le `keyId` a déjà été publié ou consommé.
    """
    if not current_agent.e2ee_signing_public_key or not current_agent.e2ee_one_time_prekeys_json:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Trousseau public initial absent : publiez d'abord vos clés via /api/e2ee/keys.",
        )

    canonical_list_json = json.dumps(req.new_one_time_prekeys, separators=(",", ":"))
    signed_message = f"REPLENISH_PREKEYS:{current_agent.matricule}:{canonical_list_json}".encode("utf-8")
    if not verify_ecdsa_p256_jwk_signature(
        public_jwk_json=current_agent.e2ee_signing_public_key,
        message_bytes=signed_message,
        signature_hex=req.signature_hex,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Signature ECDSA P-256 du lot de réapprovisionnement de pré-clés invalide.",
        )

    with _PREKEY_RESERVATION_LOCK:
        db.expire_all()
        agent = db.query(EnrolledAgent).filter(EnrolledAgent.id == current_agent.id).first()
        try:
            parsed = json.loads(agent.e2ee_one_time_prekeys_json)
            sig_bundle = parsed["signal_prekey_bundle"]
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Bundle Signal existant invalide.",
            ) from exc

        otpk_list: List[Dict[str, Any]] = list(sig_bundle.get("oneTimePreKeys") or [])
        consumed_ids: List[int] = [
            int(k)
            for k in (sig_bundle.get("consumedPreKeyIds") or [])
            if isinstance(k, (int, str)) and str(k).isdigit()
        ]
        existing_ids = {
            int(pk["keyId"])
            for pk in otpk_list
            if isinstance(pk, dict) and isinstance(pk.get("keyId"), (int, str)) and str(pk.get("keyId")).isdigit()
        }
        forbidden_ids = existing_ids.union(set(consumed_ids))

        validated_new: List[Dict[str, Any]] = []
        batch_ids = set()
        for item in req.new_one_time_prekeys:
            if not isinstance(item, dict):
                raise HTTPException(status_code=400, detail="Format de pré-clé invalide.")
            raw_id = item.get("keyId")
            pub_b64 = item.get("publicKeyB64")
            if not isinstance(raw_id, int) or raw_id <= 0 or not isinstance(pub_b64, str) or len(pub_b64) < 16:
                raise HTTPException(
                    status_code=400,
                    detail="Chaque pré-clé doit comporter un keyId entier strictement positif et publicKeyB64.",
                )
            if raw_id in forbidden_ids or raw_id in batch_ids:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"REJET SÉCURITÉ SIGNAL X3DH : Réutilisation interdite du keyId={raw_id} "
                        "(pré-clé déjà consommée ou déjà présente dans le stock)."
                    ),
                )
            batch_ids.add(raw_id)
            validated_new.append({"keyId": raw_id, "publicKeyB64": pub_b64})

        otpk_list.extend(validated_new)
        sig_bundle["oneTimePreKeys"] = otpk_list
        sig_bundle["preKey"] = otpk_list[0] if otpk_list else None
        sig_bundle["consumedPreKeyIds"] = consumed_ids
        agent.e2ee_one_time_prekeys_json = json.dumps(parsed, separators=(",", ":"))

        db.add(
            SecurityAuditLog(
                event_type="PREKEY_REPLENISHED",
                severity="INFO",
                actor_pseudonym=pseudonymize_identifier(current_agent.matricule),
                description=(
                    f"Réapprovisionnement authentifié de {len(validated_new)} One-Time PreKeys Signal "
                    f"pour {current_agent.matricule} (total disponible={len(otpk_list)})."
                ),
                timestamp_bucket=get_timestamp_bucket(),
            )
        )
        db.commit()

    return {
        "status": "PREKEYS_REPLENISHED",
        "matricule": current_agent.matricule,
        "added_count": len(validated_new),
        "remaining_one_time_prekeys": len(otpk_list),
    }


@app.get("/api/directory")
def get_official_ministry_directory(
    ministry: Optional[str] = Query(default=None),
    current_agent: EnrolledAgent = Depends(get_current_agent),
    db: Session = Depends(get_db),
):
    query = db.query(EnrolledAgent)
    # Les comptes en attente ne sont visibles que par les responsables qui peuvent
    # intervenir (réémettre une invitation). Les agents ordinaires ne voient que
    # l'annuaire des comptes activés.
    if current_agent.role == "POINT_FOCAL":
        query = query.filter(EnrolledAgent.ministry == current_agent.ministry)
    elif current_agent.role != "SUPER_ADMIN_DGTD":
        query = query.filter(EnrolledAgent.is_enrolled_activated == True)  # noqa: E712
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
            "is_enrolled_activated": ag.is_enrolled_activated,
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
                "one_time_prekeys_json": _sanitize_public_prekey_bundle_for_directory(
                    ag.e2ee_one_time_prekeys_json
                ),
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
# 4. CANAUX INSTITUTIONNELS, SESSIONS SIGNAL & MESSAGERIE CHIFFRÉE E2EE
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
            .filter(
                ChannelMember.channel_id == ch.id,
                EnrolledAgent.is_revoked == False,  # noqa: E712
                EnrolledAgent.is_enrolled_activated == True,  # noqa: E712
            )
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
                        "e2ee_one_time_prekeys_json": _sanitize_public_prekey_bundle_for_directory(
                            m.e2ee_one_time_prekeys_json
                        ),
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
            sig_hex = bundle.get("senderSignatureHex")
            if sig_hex and current_agent.e2ee_signing_public_key:
                wrap_msg = (
                    f"WRAP:{channel_id}:{req.crypto_epoch}:{matricule}:{bundle['ivB64']}:{bundle['wrappedKeyB64']}"
                ).encode("utf-8")
                if not verify_ecdsa_p256_jwk_signature(
                    public_jwk_json=current_agent.e2ee_signing_public_key,
                    message_bytes=wrap_msg,
                    signature_hex=sig_hex,
                ):
                    raise HTTPException(
                        status_code=400,
                        detail=f"Signature ECDSA P-256 invalide sur l'enveloppe de clé de groupe pour {matricule}.",
                    )
            incoming[matricule] = {
                "senderMatricule": bundle["senderMatricule"],
                "ivB64": bundle["ivB64"],
                "wrappedKeyB64": bundle["wrappedKeyB64"],
                "senderSignatureHex": sig_hex or "",
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
    current_agent: EnrolledAgent = Depends(require_account_manager),
    db: Session = Depends(get_db),
):
    if current_agent.role not in ("SUPER_ADMIN_DGTD", "POINT_FOCAL"):
        raise HTTPException(status_code=403, detail="La création de conversations est réservée à la DGTD et aux points focaux.")
    if current_agent.role == "POINT_FOCAL" and not _ministry_scope_matches(
        req.ministry_scope, current_agent.ministry
    ):
        raise HTTPException(status_code=403, detail="Un point focal ne peut créer que des conversations de son ministère.")

    requested_ids = set(req.member_ids + [current_agent.id])
    members = db.query(EnrolledAgent).filter(
        EnrolledAgent.id.in_(requested_ids),
        EnrolledAgent.is_revoked == False,  # noqa: E712
        EnrolledAgent.is_enrolled_activated == True,  # noqa: E712
    ).all()
    if len(members) != len(requested_ids):
        raise HTTPException(status_code=400, detail="Un ou plusieurs membres sont introuvables ou désactivés.")
    if current_agent.role == "POINT_FOCAL" and any(
        not _same_ministry(member.ministry, current_agent.ministry) for member in members
    ):
        raise HTTPException(status_code=403, detail="Un point focal ne peut créer une conversation que pour son ministère.")

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

    for member in members:
        db.add(ChannelMember(channel_id=channel.id, agent_id=member.id))

    _record_audit_event(
        db,
        current_agent,
        "CHANNEL_CREATED",
        f"Conversation créée (canal #{channel.id}, {len(members)} membre(s)); contenu non journalisé.",
    )

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

    if req.e2ee_protocol != SUPPORTED_E2EE_PROTOCOL:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"PROTOCOLE E2EE REJETÉ (ANTI-DOWNGRADE) : Le protocole '{req.e2ee_protocol}' n'est pas autorisé. "
                f"Seul le protocole Signal ('{SUPPORTED_E2EE_PROTOCOL}') est accepté."
            ),
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
        e2ee_protocol=req.e2ee_protocol or "SIGNAL_X3DH_DOUBLERATCHET_AES256GCM_ECDSA",
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
    _record_audit_event(
        db,
        current_agent,
        "MESSAGE_SENT",
        f"Message chiffré envoyé dans le canal #{channel_id}; contenu non journalisé.",
    )
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
    _record_audit_event(
        db,
        current_agent,
        "ATTACHMENT_UPLOADED",
        f"Pièce jointe chiffrée déposée dans le canal #{req.channel_id}; nom et contenu non journalisés.",
    )
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

    _record_audit_event(
        db,
        current_agent,
        "ATTACHMENT_DOWNLOADED",
        f"Pièce jointe chiffrée téléchargée depuis le canal #{blob.channel_id}; contenu non journalisé.",
    )
    db.commit()

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
    _record_audit_event(
        db,
        current_agent,
        "READ_RECEIPT_SIGNED",
        f"Confirmation de lecture signée pour le message #{message_id}; signature exclue du journal.",
    )
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
    response: Response,
    admin_agent: EnrolledAgent = Depends(require_account_manager),
    db: Session = Depends(get_db),
):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    matricule_clean = req.matricule.strip().upper()
    if admin_agent.role == "POINT_FOCAL":
        if req.role != "AGENT_PUBLIC":
            raise HTTPException(status_code=403, detail="Un point focal ne peut attribuer que le rôle Agent public.")
        if not _same_ministry(req.ministry, admin_agent.ministry):
            raise HTTPException(status_code=403, detail="Un point focal ne peut inscrire que des agents de son ministère.")
    elif req.role != "AGENT_PUBLIC" and admin_agent.role != "SUPER_ADMIN_DGTD":
        raise HTTPException(status_code=403, detail="Seule la DGTD peut attribuer un rôle privilégié.")

    if db.query(EnrolledAgent).filter(EnrolledAgent.matricule == matricule_clean).first():
        raise HTTPException(status_code=400, detail="Ce matricule est déjà enrôlé.")

    activation_code, activation_hash, activation_expiry = generate_activation_code()
    new_agent = EnrolledAgent(
        matricule=matricule_clean,
        full_name=req.full_name,
        ministry=req.ministry,
        direction=req.direction,
        job_title=req.job_title,
        role=req.role,
        preferred_lang=req.preferred_lang,
        # Valeurs aléatoires inutilisables avant activation; l'agent choisira
        # lui-même son mot de passe et recevra son propre secret TOTP.
        password_hash=hash_password(secrets.token_urlsafe(32)),
        must_change_password=False,
        totp_secret_encrypted=encrypt_totp_secret_at_rest(generate_totp_secret()),
        totp_enabled=False,
        enrolment_token=activation_hash,
        enrolment_token_expires_at=activation_expiry,
        is_enrolled_activated=False,
        is_demo_account=False,
        is_revoked=False,
        token_version=1,
    )
    db.add(new_agent)
    db.flush()

    default_channels = db.query(Channel).filter(
        (Channel.ministry_scope == "TOUS") | (Channel.ministry_scope == req.ministry)
    ).all()
    for ch in default_channels:
        db.add(ChannelMember(channel_id=ch.id, agent_id=new_agent.id))

    _record_audit_event(
        db,
        admin_agent,
        "AGENT_ENROLLED",
        f"Compte {pseudonymize_identifier(matricule_clean)} créé pour le ministère {req.ministry}; rôle {req.role}.",
    )
    db.commit()

    return {
        "id": new_agent.id,
        "matricule": new_agent.matricule,
        "full_name": new_agent.full_name,
        "activation_code_once": activation_code,
        "activation_expires_at": activation_expiry.isoformat() + "Z",
    }


@app.post("/api/admin/agents/{agent_id}/activation-code")
def reissue_agent_activation_code(
    agent_id: int,
    response: Response,
    admin_agent: EnrolledAgent = Depends(require_account_manager),
    db: Session = Depends(get_db),
):
    """Invalidate a lost invitation and issue a replacement to an unactivated agent."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    target = db.query(EnrolledAgent).filter(EnrolledAgent.id == agent_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Agent introuvable.")
    if target.is_enrolled_activated:
        raise HTTPException(status_code=409, detail="Ce compte est déjà activé.")
    if target.is_revoked:
        raise HTTPException(status_code=409, detail="Ce compte est révoqué; rétablissez-le avant de réémettre une invitation.")
    if admin_agent.role == "POINT_FOCAL" and (
        target.role != "AGENT_PUBLIC" or not _same_ministry(target.ministry, admin_agent.ministry)
    ):
        raise HTTPException(status_code=403, detail="Un point focal ne peut réémettre que pour un agent public de son ministère.")

    code, code_hash, expires_at = generate_activation_code()
    target.enrolment_token = code_hash
    target.enrolment_token_expires_at = expires_at
    target.totp_secret_encrypted = encrypt_totp_secret_at_rest(generate_totp_secret())
    target.totp_enabled = False
    target.token_version += 1  # invalide toute session d'activation déjà remise
    _record_audit_event(
        db,
        admin_agent,
        "ACCOUNT_ACTIVATION_CODE_REISSUED",
        f"Nouveau code d'activation émis pour {pseudonymize_identifier(target.matricule)}.",
        severity="WARNING",
    )
    db.commit()
    return {
        "id": target.id,
        "matricule": target.matricule,
        "activation_code_once": code,
        "activation_expires_at": expires_at.isoformat() + "Z",
    }


@app.patch("/api/admin/agents/{agent_id}/role")
def change_agent_role(
    agent_id: int,
    req: ChangeAgentRoleRequest,
    admin_agent: EnrolledAgent = Depends(require_super_admin),
    db: Session = Depends(get_db),
):
    target = db.query(EnrolledAgent).filter(EnrolledAgent.id == agent_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Agent introuvable.")
    if target.id == admin_agent.id:
        raise HTTPException(status_code=400, detail="Vous ne pouvez pas modifier votre propre rôle.")
    if target.role == "SUPER_ADMIN_DGTD" and req.role != "SUPER_ADMIN_DGTD":
        active_super_admins = db.query(EnrolledAgent).filter(
            EnrolledAgent.role == "SUPER_ADMIN_DGTD",
            EnrolledAgent.is_revoked == False,  # noqa: E712
            EnrolledAgent.is_enrolled_activated == True,  # noqa: E712
        ).count()
        if active_super_admins <= 1:
            raise HTTPException(status_code=409, detail="Le dernier administrateur DGTD actif doit être conservé.")

    old_role = target.role
    if old_role == req.role:
        return {"status": "UNCHANGED", "agent_id": target.id, "role": target.role}

    target.role = req.role
    _record_audit_event(
        db,
        admin_agent,
        "AGENT_ROLE_CHANGED",
        f"Rôle modifié pour {pseudonymize_identifier(target.matricule)} : {old_role} → {req.role}.",
        severity="WARNING" if req.role != "AGENT_PUBLIC" else "INFO",
    )
    db.commit()
    return {"status": "ROLE_CHANGED", "agent_id": target.id, "role": target.role}


@app.post("/api/admin/revoke/{agent_id}")
async def revoke_agent_immediately(
    agent_id: int,
    req: RevokeAgentRequest,
    admin_agent: EnrolledAgent = Depends(require_account_manager),
    db: Session = Depends(get_db),
):
    target = db.query(EnrolledAgent).filter(EnrolledAgent.id == agent_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Agent introuvable.")
    if target.id == admin_agent.id:
        raise HTTPException(status_code=400, detail="Vous ne pouvez pas désactiver votre propre compte.")
    if admin_agent.role == "POINT_FOCAL":
        if target.role != "AGENT_PUBLIC" or not _same_ministry(target.ministry, admin_agent.ministry):
            raise HTTPException(status_code=403, detail="Un point focal ne peut désactiver que les agents publics de son ministère.")
    if target.role == "SUPER_ADMIN_DGTD":
        active_super_admins = db.query(EnrolledAgent).filter(
            EnrolledAgent.role == "SUPER_ADMIN_DGTD",
            EnrolledAgent.is_revoked == False,  # noqa: E712
            EnrolledAgent.is_enrolled_activated == True,  # noqa: E712
        ).count()
        if active_super_admins <= 1:
            raise HTTPException(status_code=409, detail="Le dernier administrateur DGTD actif ne peut pas être désactivé.")

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
            try:
                bundles = json.loads(ch.encrypted_group_session_bundles or "{}")
                for ep_dict in bundles.values():
                    if isinstance(ep_dict, dict):
                        ep_dict.pop(target.matricule, None)
                ch.encrypted_group_session_bundles = json.dumps(bundles)
            except Exception:
                ch.encrypted_group_session_bundles = "{}"
        rem_rows = (
            db.query(ChannelMember.agent_id)
            .filter(ChannelMember.channel_id.in_(affected_channel_ids))
            .all()
        )
        remaining_agent_ids = {r[0] for r in rem_rows if r[0] != target.id}

    _record_audit_event(
        db,
        admin_agent,
        "AGENT_REVOKED_IMMEDIATELY",
        f"Compte {pseudonymize_identifier(target.matricule)} désactivé; jetons invalidés, retrait de {len(affected_channel_ids)} canaux et rotation des clés de groupe.",
        severity="CRITICAL",
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
    admin_agent: EnrolledAgent = Depends(require_account_manager),
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
    if admin_agent.role == "POINT_FOCAL" and (
        target.role != "AGENT_PUBLIC" or not _same_ministry(target.ministry, admin_agent.ministry)
    ):
        raise HTTPException(status_code=403, detail="Un point focal ne peut réactiver que les agents publics de son ministère.")

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
                "sender_pseudonymization": (
                    "HMAC-SHA256 au repos en base SQL (évite les matricules en clair dans les colonnes SQL ; "
                    "non anonyme face au serveur actif qui authentifie le JWT et détient METADATA_HMAC_PEPPER)"
                ),
                "classification_and_flags_in_db": "SEALED_E2EE (no_forward, anti_screenshot et classification chiffrés dans ciphertext_payload)",
                "message_padding": "Blocs de 256 octets avant chiffrement Signal Double Ratchet",
                "timestamp_granularity": "Arrondi par tranche de 5 minutes (aucun created_at milliseconde)",
                "attachment_padding": "Blocs de 4096 octets (masquage de la taille exacte avant chiffrement AES-256-GCM)",
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
async def websocket_endpoint(
    websocket: WebSocket,
    ticket: str = Query(..., min_length=32, max_length=128),
):
    db = SessionLocal()
    agent_id: Optional[int] = None
    try:
        ticket_hash = hashlib.sha256(ticket.encode("utf-8")).hexdigest()
        # SQLite recharge les colonnes DateTime sans fuseau horaire ; conserver
        # les comparaisons et l'écriture du ticket en UTC naïf.
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        consumed = (
            db.query(WebSocketTicket)
            .filter(
                WebSocketTicket.ticket_hash == ticket_hash,
                WebSocketTicket.consumed_at.is_(None),
                WebSocketTicket.expires_at > now,
            )
            .update({WebSocketTicket.consumed_at: now}, synchronize_session=False)
        )
        if consumed != 1:
            db.rollback()
            await websocket.close(code=4003)
            return
        db.commit()

        ticket_row = db.query(WebSocketTicket).filter(
            WebSocketTicket.ticket_hash == ticket_hash
        ).first()
        if not ticket_row:
            await websocket.close(code=4003)
            return

        ticket_agent_id = ticket_row.agent_id
        ticket_token_version = ticket_row.token_version
        agent = db.query(EnrolledAgent).filter(EnrolledAgent.id == ticket_agent_id).first()
        if (
            not agent
            or not agent.is_enrolled_activated
            or agent.is_revoked
            or agent.token_version != ticket_token_version
        ):
            await websocket.close(code=4003)
            return

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
