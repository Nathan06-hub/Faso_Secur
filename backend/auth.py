"""
Module d'Authentification Forte (2FA TOTP RFC 6238 chiffré au repos par Fernet),
de Vérification de Signatures Cryptographiques ECDSA P-256, de Rate-Limiting Brute-Force,
de Révocation Immédiate et de Minimisation des Métadonnées pour FASO-SÉCUR.

Bibliothèques Open Source utilisées (aucune cryptographie maison) :
- `bcrypt` (Apache 2.0) : Hachage adaptatif des mots de passe administratifs
- `cryptography` (Apache 2.0 / BSD - PyCA) :
  - `Fernet` (AES-128-CBC + HMAC-SHA256) : Chiffrement au repos des secrets `totp_secret` en BDD
  - `TOTP` (RFC 6238) : Second facteur d'authentification
  - `ec.SECP256R1` (ECDSA P-256 / SHA-256) : Vérification mathématique des signatures E2EE
- `PyJWT` (MIT) : Jetons de session signés avec vérification de révocation en temps réel
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import bcrypt
import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.twofactor.totp import InvalidToken, TOTP
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from database import get_db
from models import EnrolledAgent

# Clés serveur générées par CSPRNG au démarrage si non injectées par l'environnement
# (Aucun secret statique codé en dur dans le code source)
JWT_SECRET_KEY = os.getenv("FASO_SECUR_JWT_SECRET") or secrets.token_urlsafe(48)
METADATA_HMAC_PEPPER = os.getenv("FASO_SECUR_METADATA_PEPPER") or secrets.token_urlsafe(32)

# Clé Fernet (32 octets encodés en Base64 URL-safe) pour chiffrer `totp_secret` au repos en BDD
_RAW_FERNET_ENV = os.getenv("FASO_SECUR_TOTP_FERNET_KEY")
if _RAW_FERNET_ENV:
    _FERNET_KEY = base64.urlsafe_b64encode(hashlib.sha256(_RAW_FERNET_ENV.encode("utf-8")).digest())
else:
    _FERNET_KEY = Fernet.generate_key()

_totp_fernet = Fernet(_FERNET_KEY)

# Par défaut en production, DEMO_MODE est désactivé sauf si explicitement activé (ex: tests / démo jury)
DEMO_MODE_ENABLED = os.getenv("FASO_SECUR_DEMO_MODE", "false").lower() in ("1", "true", "yes")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480

security_bearer = HTTPBearer(auto_error=False)


# ============================================================================
# 0. PROTECTION ANTI-BRUTE-FORCE (RATE LIMITING SUR LE LOGIN)
# ============================================================================

class LoginRateLimiter:
    def __init__(self, max_attempts: int = 5, window_seconds: int = 300) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._failures: Dict[str, List[float]] = defaultdict(list)

    def check_allowed(self, identifier: str) -> None:
        now = time.time()
        key = identifier.strip().upper()
        self._failures[key] = [
            ts for ts in self._failures[key] if now - ts < self.window_seconds
        ]
        if len(self._failures[key]) >= self.max_attempts:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"PROTECTION ANTI-BRUTE-FORCE : Trop de tentatives échouées pour '{key}'. "
                    "Compte temporairement verrouillé pendant 5 minutes."
                ),
            )

    def record_failure(self, identifier: str) -> None:
        key = identifier.strip().upper()
        self._failures[key].append(time.time())

    def reset(self, identifier: str) -> None:
        key = identifier.strip().upper()
        self._failures.pop(key, None)


login_rate_limiter = LoginRateLimiter(max_attempts=5, window_seconds=300)


# ============================================================================
# 1. HACHAGE DE MOT DE PASSE (BCRYPT - OPEN SOURCE)
# ============================================================================

def hash_password(plain_password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain_password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            password_hash.encode("utf-8"),
        )
    except Exception:
        return False


# ============================================================================
# 2. SECOND FACTEUR 2FA TOTP (RFC 6238) & CHIFFREMENT AU REPOS FERNET
# ============================================================================

def generate_totp_secret() -> str:
    """Génère un secret TOTP de 160 bits encodé en Base32 conformément à la RFC 6238."""
    raw_secret = secrets.token_bytes(20)
    return base64.b32encode(raw_secret).decode("utf-8")


def encrypt_totp_secret_at_rest(plain_base32_secret: str) -> str:
    """
    Chiffre le secret Base32 TOTP avec Fernet (AES-128-CBC + HMAC-SHA256 de PyCA cryptography)
    avant son stockage en base de données (`totp_secret_encrypted`).
    Un `SELECT * FROM enrolled_agents` ne révèle jamais le secret 2FA en clair.
    """
    return _totp_fernet.encrypt(plain_base32_secret.strip().encode("utf-8")).decode("utf-8")


def decrypt_totp_secret_at_rest(encrypted_token: str) -> str:
    """Déchiffre en mémoire vive le secret TOTP Fernet pour la vérification RFC 6238."""
    return _totp_fernet.decrypt(encrypted_token.encode("utf-8")).decode("utf-8")


def _build_pyca_totp(base32_secret: str) -> TOTP:
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


def generate_current_totp_code(encrypted_or_plain_secret: str, timestamp: Optional[float] = None) -> str:
    """Génère le code TOTP à 6 chiffres pour l'instant courant."""
    base32_secret = (
        decrypt_totp_secret_at_rest(encrypted_or_plain_secret)
        if encrypted_or_plain_secret.startswith("gAAAAA")
        else encrypted_or_plain_secret
    )
    totp = _build_pyca_totp(base32_secret)
    ts = int(timestamp if timestamp is not None else time.time())
    return totp.generate(ts).decode("utf-8")


def verify_totp_code(encrypted_or_plain_secret: str, code: str, window: int = 1) -> bool:
    """Vérifie un code TOTP à 6 chiffres selon la RFC 6238 en déchiffrant d'abord le jeton Fernet."""
    if not code or not code.strip().isdigit() or len(code.strip()) != 6:
        return False
    try:
        base32_secret = (
            decrypt_totp_secret_at_rest(encrypted_or_plain_secret)
            if encrypted_or_plain_secret.startswith("gAAAAA")
            else encrypted_or_plain_secret
        )
    except Exception:
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
    issuer = f"FASO-SECUR ({ministry})"
    return (
        f"otpauth://totp/{issuer}:{matricule}"
        f"?secret={base32_secret}&issuer=FASO-SECUR-DGTD&algorithm=SHA1&digits=6&period=30"
    )


# ============================================================================
# 3. VÉRIFICATION CRYPTOGRAPHIQUE DES SIGNATURES ECDSA P-256 & SAFETY NUMBER
# ============================================================================

def _b64url_decode_to_int(b64url_str: str) -> int:
    padding = (4 - len(b64url_str) % 4) % 4
    raw = base64.urlsafe_b64decode(b64url_str + ("=" * padding))
    return int.from_bytes(raw, byteorder="big")


def verify_ecdsa_p256_jwk_signature(
    public_jwk_json: str,
    message_bytes: bytes,
    signature_hex: str,
) -> bool:
    """
    Vérifie mathématiquement une signature ECDSA P-256 (format IEEE P1363 64 octets `r || s`
    issu de W3C WebCrypto ou format ASN.1 DER) avec la clé publique JWK de l'agent
    enregistrée dans l'annuaire souverain (`current_agent.e2ee_signing_public_key`).
    """
    try:
        jwk = json.loads(public_jwk_json) if isinstance(public_jwk_json, str) else public_jwk_json
        if not isinstance(jwk, dict) or jwk.get("crv") != "P-256" or "x" not in jwk or "y" not in jwk:
            return False

        x_int = _b64url_decode_to_int(jwk["x"])
        y_int = _b64url_decode_to_int(jwk["y"])
        pub_numbers = ec.EllipticCurvePublicNumbers(x_int, y_int, ec.SECP256R1())
        public_key = pub_numbers.public_key()

        sig_bytes = bytes.fromhex(signature_hex.strip())
        if len(sig_bytes) == 64:
            r = int.from_bytes(sig_bytes[:32], byteorder="big")
            s = int.from_bytes(sig_bytes[32:], byteorder="big")
            der_sig = encode_dss_signature(r, s)
        else:
            der_sig = sig_bytes

        public_key.verify(der_sig, message_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False


def compute_key_safety_number(matricule: str, identity_pub_json: str, signing_pub_json: str) -> str:
    """
    Calcule un Numéro de Sécurité (Safety Number) à 30 chiffres (6 blocs de 5 chiffres)
    à partir du SHA-256 canonique du matricule et des clés publiques ECDH + ECDSA de l'agent.
    Permet aux agents de comparer leurs empreintes hors-bande pour détecter toute substitution
    de clé publique par un serveur compromis.
    """
    canonical = f"SAFETY_NUMBER_V1::{matricule.strip().upper()}::{identity_pub_json.strip()}::{signing_pub_json.strip()}"
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    groups = []
    for i in range(0, 24, 4):
        val = int.from_bytes(digest[i : i + 4], byteorder="big") % 100000
        groups.append(f"{val:05d}")
    return " ".join(groups)


# ============================================================================
# 4. GESTION DES JETONS JWT & CONTRÔLE DE RÉVOCATION IMMÉDIATE
# ============================================================================

def create_access_token(agent: EnrolledAgent) -> str:
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
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentification requise (jeton Bearer absent).",
        )
    return verify_and_load_active_agent(credentials.credentials, db)


def require_admin_role(current_agent: EnrolledAgent = Depends(get_current_agent)) -> EnrolledAgent:
    if current_agent.role not in ("SUPER_ADMIN_DGTD", "POINT_FOCAL", "AUDITEUR"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Action réservée aux administrateurs ou auditeurs habilités (DGTD / Point Focal).",
        )
    return current_agent


# ============================================================================
# 5. MINIMISATION DES MÉTADONNÉES CÔTÉ SERVEUR (PSEUDONYMISATION HMAC & BUCKETING)
# ============================================================================

def pseudonymize_identifier(raw_identifier: str) -> str:
    digest = hmac.new(
        METADATA_HMAC_PEPPER.encode("utf-8"),
        raw_identifier.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"pseudo_{digest[:16]}"


def get_timestamp_bucket(dt: Optional[datetime] = None) -> str:
    now = dt or datetime.now(timezone.utc)
    bucket_minute = (now.minute // 5) * 5
    return now.strftime(f"%Y-%m-%dT%H:{bucket_minute:02d}:00Z")
