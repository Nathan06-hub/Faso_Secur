"""
Module d'Authentification Forte (2FA TOTP RFC 6238), de Gestion des Rôles (RBAC),
de Révocation Immédiate et de Minimisation des Métadonnées pour FASO-SÉCUR.

Bibliothèques Open Source utilisées (aucune cryptographie maison) :
- `bcrypt` (Apache 2.0) : Hachage adaptatif des mots de passe administratifs
- `cryptography` (Apache 2.0 / BSD - PyCA) : Implémentation officielle RFC 6238 TOTP (Second Facteur)
- `PyJWT` (MIT) : Jetons de session signés avec vérification de révocation en temps réel
"""

import base64
import hashlib
import hmac
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.twofactor.totp import InvalidToken, TOTP
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from database import get_db
from models import EnrolledAgent

# Clés serveur souveraines (configurables par variables d'environnement dans Docker Compose)
JWT_SECRET_KEY = os.getenv(
    "FASO_SECUR_JWT_SECRET",
    "bf-dgtd-sovereign-jwt-secret-key-2026-hackathon226-open-source",
)
METADATA_HMAC_PEPPER = os.getenv(
    "FASO_SECUR_METADATA_PEPPER",
    "bf-dgtd-metadata-minimization-pepper-2026",
)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 heures (journée de service)

security_bearer = HTTPBearer(auto_error=False)


# ============================================================================
# 1. HACHAGE DE MOT DE PASSE (BCRYPT - OPEN SOURCE)
# ============================================================================

def hash_password(plain_password: str) -> str:
    """Hache le mot de passe d'un agent avec un sel aléatoire via bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain_password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Vérifie de manière résistante aux attaques temporelles le mot de passe avec bcrypt."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            password_hash.encode("utf-8"),
        )
    except Exception:
        return False


# ============================================================================
# 2. SECOND FACTEUR D'AUTHENTIFICATION (TOTP RFC 6238 via PyCA cryptography)
# ============================================================================

def generate_totp_secret() -> str:
    """
    Génère un secret TOTP de 160 bits (20 octets) encodé en Base32 conformément à la RFC 6238.
    Ce secret est partagé lors de l'enrôlement de l'agent public.
    """
    raw_secret = secrets.token_bytes(20)
    return base64.b32encode(raw_secret).decode("utf-8")


def _build_pyca_totp(base32_secret: str) -> TOTP:
    """Construit une instance TOTP officielle de la bibliothèque PyCA cryptography."""
    normalized = base32_secret.upper().strip()
    padding = (8 - len(normalized) % 8) % 8
    raw_key = base64.b32decode(normalized + ("=" * padding))
    return TOTP(
        key=raw_key,
        length=6,
        algorithm=SHA1(),
        time_step=30,
        enforce_key_length=False,
    )


def generate_current_totp_code(base32_secret: str, timestamp: Optional[float] = None) -> str:
    """
    Génère le code TOTP à 6 chiffres pour l'instant courant (fenêtre de 30 secondes).
    Utilisé par les tests automatisés et le simulateur d'application 2FA de démonstration.
    """
    totp = _build_pyca_totp(base32_secret)
    ts = int(timestamp if timestamp is not None else time.time())
    return totp.generate(ts).decode("utf-8")


def verify_totp_code(base32_secret: str, code: str, window: int = 1) -> bool:
    """
    Vérifie un code TOTP à 6 chiffres selon la RFC 6238 (avec tolérance d'horloge +-1 palier de 30s).
    S'appuie exclusivement sur `cryptography.hazmat.primitives.twofactor.totp.TOTP`.
    """
    if not code or not code.strip().isdigit() or len(code.strip()) != 6:
        return False
    totp = _build_pyca_totp(base32_secret)
    now = int(time.time())
    code_bytes = code.strip().encode("utf-8")
    for offset in range(-window, window + 1):
        try:
            totp.verify(code_bytes, now + (offset * 30))
            return True
        except InvalidToken:
            continue
    return False


def build_otpauth_uri(matricule: str, ministry: str, base32_secret: str) -> str:
    """Construit l'URI standard otpauth:// pour FreeOTP / Aegis Authenticator."""
    issuer = f"FASO-SECUR ({ministry})"
    return (
        f"otpauth://totp/{issuer}:{matricule}"
        f"?secret={base32_secret}&issuer=FASO-SECUR-DGTD&algorithm=SHA1&digits=6&period=30"
    )


# ============================================================================
# 3. GESTION DES JETONS JWT & CONTRÔLE DE RÉVOCATION IMMÉDIATE
# ============================================================================

def create_access_token(agent: EnrolledAgent) -> str:
    """
    Émet un jeton JWT signé contenant le matricule, le rôle et la version de jeton (`token_version`).
    Si l'agent est révoqué, `is_revoked` passe à True et `token_version` est incrémenté,
    ce qui invalide immédiatement tous ses jetons existants sur tous ses appareils.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": agent.matricule,
        "agent_id": agent.id,
        "role": agent.role,
        "ministry": agent.ministry,
        "token_version": agent.token_version,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_and_load_active_agent(token: str, db: Session) -> EnrolledAgent:
    """
    Vérifie la signature du JWT ET consulte en temps réel l'état d'enrôlement et de révocation.
    Garantit l'épreuve du jury « Révocation » et « Intrus » :
    - Si le compte n'est pas enrôlé -> 403 Forbidden
    - Si l'agent a été révoqué -> 403 Forbidden immédiat
    - Si `token_version` ne correspond plus -> 401 Unauthorized immédiat
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Jeton d'authentification invalide ou expiré.",
        ) from exc

    matricule = payload.get("sub")
    token_version = payload.get("token_version")
    if not matricule:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Jeton malformé (matricule absent).",
        )

    agent = db.query(EnrolledAgent).filter(EnrolledAgent.matricule == matricule).first()
    if not agent or not agent.is_enrolled_activated:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Accès refusé : agent non enrôlé dans l'annuaire souverain DGTD.",
        )

    if agent.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"ACCÈS RÉVOQUÉ IMMÉDIATEMENT ({agent.revocation_reason or 'Révocation administrative DGTD'}).",
        )

    if agent.token_version != token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session invalidée suite à une révocation ou rotation de sécurité.",
        )

    return agent


def get_current_agent(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    db: Session = Depends(get_db),
) -> EnrolledAgent:
    """Dépendance FastAPI protégeant chaque route REST par authentification forte + contrôle de révocation."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentification requise (jeton Bearer absent).",
        )
    return verify_and_load_active_agent(credentials.credentials, db)


def require_admin_role(current_agent: EnrolledAgent = Depends(get_current_agent)) -> EnrolledAgent:
    """Vérifie que l'agent dispose d'un rôle d'administration (DGTD ou Point Focal Ministériel)."""
    if current_agent.role not in ("SUPER_ADMIN_DGTD", "POINT_FOCAL"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Action réservée aux administrateurs habilités (DGTD / Point Focal Ministériel).",
        )
    return current_agent


# ============================================================================
# 4. MINIMISATION DES MÉTADONNÉES CÔTÉ SERVEUR (PSEUDONYMISATION HMAC & BUCKETING)
# ============================================================================

def pseudonymize_identifier(raw_identifier: str) -> str:
    """
    Transforme un matricule ou identifiant en pseudonyme cryptographique non réversible
    via HMAC-SHA256 afin de minimiser les métadonnées stockées en base de données et dans les journaux.
    """
    digest = hmac.new(
        METADATA_HMAC_PEPPER.encode("utf-8"),
        raw_identifier.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"pseudo_{digest[:16]}"


def get_timestamp_bucket(dt: Optional[datetime] = None) -> str:
    """
    Arrondit l'horodatage par tranche de 5 minutes pour réduire les corrélations temporelles
    de trafic (minimisation des métadonnées temporelles côté serveur).
    """
    now = dt or datetime.now(timezone.utc)
    bucket_minute = (now.minute // 5) * 5
    return now.strftime(f"%Y-%m-%dT%H:{bucket_minute:02d}:00Z")
