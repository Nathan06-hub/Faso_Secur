"""
Module d'Authentification Forte (2FA TOTP RFC 6238), de Vérification de Signatures
Cryptographiques ECDSA P-256, de Rate-Limiting Brute-Force, de Révocation Immédiate
et de Minimisation des Métadonnées pour FASO-SÉCUR.

Bibliothèques Open Source utilisées (aucune cryptographie maison) :
- `bcrypt` (Apache 2.0) : Hachage adaptatif des mots de passe administratifs
- `cryptography` (Apache 2.0 / BSD - PyCA) :
  - RFC 6238 TOTP (Second Facteur)
  - Vérification cryptographique des signatures ECDSA P-256 (messages E2EE & accusés probants)
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

# Clés serveur souveraines injectées par l'environnement (avec génération CSPRNG de secours)
_DEFAULT_EPHEMERAL_JWT = secrets.token_urlsafe(48)
JWT_SECRET_KEY = os.getenv("FASO_SECUR_JWT_SECRET", _DEFAULT_EPHEMERAL_JWT)
METADATA_HMAC_PEPPER = os.getenv(
    "FASO_SECUR_METADATA_PEPPER",
    "bf-dgtd-metadata-minimization-pepper-2026",
)
DEMO_MODE_ENABLED = os.getenv("FASO_SECUR_DEMO_MODE", "true").lower() in ("1", "true", "yes")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480

security_bearer = HTTPBearer(auto_error=False)


# ============================================================================
# 0. PROTECTION ANTI-BRUTE-FORCE (RATE LIMITING SUR LE LOGIN)
# ============================================================================

class LoginRateLimiter:
    """
    Bloque automatiquement un matricule après `max_attempts` échecs d'authentification
    sur une fenêtre glissante de `window_seconds` secondes (HTTP 429 Too Many Requests).
    """

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
    """Génère un secret TOTP de 160 bits encodé en Base32 conformément à la RFC 6238."""
    raw_secret = secrets.token_bytes(20)
    return base64.b32encode(raw_secret).decode("utf-8")


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


def generate_current_totp_code(base32_secret: str, timestamp: Optional[float] = None) -> str:
    """Génère le code TOTP à 6 chiffres pour l'instant courant (fenêtre de 30 secondes)."""
    totp = _build_pyca_totp(base32_secret)
    ts = int(timestamp if timestamp is not None else time.time())
    return totp.generate(ts).decode("utf-8")


def verify_totp_code(base32_secret: str, code: str, window: int = 1) -> bool:
    """Vérifie un code TOTP à 6 chiffres selon la RFC 6238 (avec tolérance ±1 palier de 30s)."""
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
    issuer = f"FASO-SECUR ({ministry})"
    return (
        f"otpauth://totp/{issuer}:{matricule}"
        f"?secret={base32_secret}&issuer=FASO-SECUR-DGTD&algorithm=SHA1&digits=6&period=30"
    )


# ============================================================================
# 3. VÉRIFICATION CRYPTOGRAPHIQUE DES SIGNATURES ECDSA P-256 (PyCA cryptography)
# ============================================================================

def _b64url_decode_to_int(b64url_str: str) -> int:
    padding = (4 - len(b64url_str) % 4) % 4
    raw = base64.urlsafe_b64decode(b64url_str + ("=" * padding))
    return int.from_bytes(raw, byteorder="big")


def verify_ecdsa_p256_jwk_signature(
    public_jwk_json: str,
    message_bytes: bytes,
    signature_hex: str,
    prehashed_sha256: bool = False,
) -> bool:
    """
    Vérifie mathématiquement une signature ECDSA P-256 (format IEEE P1363 64 octets `r || s`
    issu de W3C WebCrypto ou format ASN.1 DER) avec la clé publique JWK de l'agent
    en s'appuyant exclusivement sur `cryptography.hazmat.primitives.asymmetric.ec`.
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

        # WebCrypto applique SHA-256 lors de `subtle.sign({name: 'ECDSA', hash: 'SHA-256'}, key, data)`
        public_key.verify(der_sig, message_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False


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
    if current_agent.role not in ("SUPER_ADMIN_DGTD", "POINT_FOCAL"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Action réservée aux administrateurs habilités (DGTD / Point Focal Ministériel).",
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
