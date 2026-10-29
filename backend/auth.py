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
import threading
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

from database import DATABASE_URL, get_db
from models import EnrolledAgent


def _read_secret_from_env_or_file(env_var: str, file_env_var: str, default_secret_path: str = "") -> str:
    """
    Lit un secret serveur par ordre de priorité :
    1. Variable d'environnement directe (`FASO_SECUR_*`)
    2. Fichier de secret monté (`FASO_SECUR_*_FILE` ou `/run/secrets/...` — Docker Secrets / Vault)
    """
    direct_val = os.getenv(env_var, "").strip()
    if direct_val:
        return direct_val
    file_path = os.getenv(file_env_var, "").strip() or default_secret_path
    if file_path and os.path.isfile(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as fh:
                content = fh.read().strip()
                if content:
                    return content
        except Exception:
            pass
    return ""


def _resolve_secrets_file_path() -> str:
    """
    Détermine l'emplacement persistant du fichier de secrets serveur dans un répertoire
    SÉPARÉ du dossier de la base de données SQLite, afin que la compromission ou la copie
    du fichier `.db` (ou de son volume `/app/data`) n'expose jamais la clé maîtresse Fernet,
    la clé JWT ni le poivre HMAC.
    """
    explicit_path = os.getenv("FASO_SECUR_SECRETS_FILE", "").strip()
    if explicit_path:
        return explicit_path
    # Par défaut, utilise un dossier dédié `.faso_secur_secrets` distinct du dossier `data/` de la BDD
    base_dir = os.path.dirname(os.path.abspath(__file__))
    secrets_dir = os.path.join(base_dir, ".faso_secur_secrets")
    return os.path.join(secrets_dir, ".faso_secur_server_secrets.json")


def _load_or_create_persistent_secrets() -> Dict[str, str]:
    secrets_path = _resolve_secrets_file_path()
    stored: Dict[str, str] = {}
    if os.path.exists(secrets_path):
        try:
            with open(secrets_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                if isinstance(data, dict):
                    stored = {str(k): str(v) for k, v in data.items() if v}
        except Exception:
            stored = {}

    changed = False
    if not stored.get("jwt_secret"):
        stored["jwt_secret"] = secrets.token_urlsafe(48)
        changed = True
    if not stored.get("metadata_pepper"):
        stored["metadata_pepper"] = secrets.token_urlsafe(32)
        changed = True
    if not stored.get("totp_fernet_key"):
        stored["totp_fernet_key"] = Fernet.generate_key().decode("utf-8")
        changed = True

    if changed:
        try:
            os.makedirs(os.path.dirname(secrets_path), exist_ok=True)
            with open(secrets_path, "w", encoding="utf-8") as fh:
                json.dump(stored, fh, indent=2)
            try:
                os.chmod(secrets_path, 0o600)
            except Exception:
                pass
        except Exception:
            pass

    return stored


def _normalize_fernet_key(raw_key: str) -> bytes:
    cleaned = raw_key.strip()
    try:
        decoded = base64.urlsafe_b64decode(cleaned.encode("utf-8"))
        if len(decoded) == 32:
            return cleaned.encode("utf-8")
    except Exception:
        pass
    return base64.urlsafe_b64encode(hashlib.sha256(cleaned.encode("utf-8")).digest())


_PERSISTENT_SECRETS = _load_or_create_persistent_secrets()

# Clés serveur fournies par l'environnement / Docker Secrets ou persistées sur un volume dédié séparé de la BDD
JWT_SECRET_KEY = (
    _read_secret_from_env_or_file(
        "FASO_SECUR_JWT_SECRET",
        "FASO_SECUR_JWT_SECRET_FILE",
        "/run/secrets/faso_secur_jwt_secret",
    )
    or _PERSISTENT_SECRETS["jwt_secret"]
)
METADATA_HMAC_PEPPER = (
    _read_secret_from_env_or_file(
        "FASO_SECUR_METADATA_PEPPER",
        "FASO_SECUR_METADATA_PEPPER_FILE",
        "/run/secrets/faso_secur_metadata_pepper",
    )
    or _PERSISTENT_SECRETS["metadata_pepper"]
)

# Clé Fernet (accepte variable directe, fichier Docker Secret `/run/secrets/faso_secur_totp_fernet_key` ou clé persistée)
_RAW_FERNET_ENV = (
    _read_secret_from_env_or_file(
        "FASO_SECUR_TOTP_FERNET_KEY",
        "FASO_SECUR_TOTP_FERNET_KEY_FILE",
        "/run/secrets/faso_secur_totp_fernet_key",
    )
    or os.getenv("FASO_SECUR_TOTP_ENCRYPTION_KEY", "").strip()
)
if _RAW_FERNET_ENV:
    _FERNET_KEY = _normalize_fernet_key(_RAW_FERNET_ENV)
else:
    _FERNET_KEY = _normalize_fernet_key(_PERSISTENT_SECRETS["totp_fernet_key"])

_totp_fernet = Fernet(_FERNET_KEY)

# Par défaut en production, DEMO_MODE est strictement désactivé (false)
DEMO_MODE_ENABLED = os.getenv("FASO_SECUR_DEMO_MODE", "false").strip().lower() in ("1", "true", "yes")
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


class PreKeyReservationRateLimiter:
    """
    Limiteur de débit dédié à la réservation des pré-clés Signal à usage unique
    (POST /api/e2ee/prekeys/consume/{target_matricule}) afin de réduire le risque
    d'épuisement volontaire (Pre-Key Exhaustion DoS) des pré-clés d'un destinataire.
    """

    def __init__(
        self,
        max_per_actor: int = 30,
        max_per_pair: int = 8,
        window_seconds: int = 60,
    ) -> None:
        self.max_per_actor = max_per_actor
        self.max_per_pair = max_per_pair
        self.window_seconds = window_seconds
        self._actor_requests: Dict[str, List[float]] = defaultdict(list)
        self._pair_requests: Dict[str, List[float]] = defaultdict(list)

    def check_and_record(self, actor_matricule: str, target_matricule: str) -> None:
        now = time.time()
        actor_key = actor_matricule.strip().upper()
        target_key = target_matricule.strip().upper()
        pair_key = f"{actor_key}->{target_key}"

        self._actor_requests[actor_key] = [
            ts for ts in self._actor_requests[actor_key] if now - ts < self.window_seconds
        ]
        self._pair_requests[pair_key] = [
            ts for ts in self._pair_requests[pair_key] if now - ts < self.window_seconds
        ]

        if (
            len(self._actor_requests[actor_key]) >= self.max_per_actor
            or len(self._pair_requests[pair_key]) >= self.max_per_pair
        ):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    "LIMITATION DE DÉBIT SIGNAL X3DH : Trop de réservations de pré-clés à usage unique "
                    f"par '{actor_key}' vers '{target_key}'. Réessayez ultérieurement."
                ),
            )

        self._actor_requests[actor_key].append(now)
        self._pair_requests[pair_key].append(now)

    def reset(self) -> None:
        self._actor_requests.clear()
        self._pair_requests.clear()


prekey_reservation_rate_limiter = PreKeyReservationRateLimiter()


class WebSocketTicketRateLimiter:
    """Limite les écritures de tickets courts par session agent authentifiée."""

    def __init__(self, max_requests: int = 20, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: Dict[int, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def check_and_record(self, agent_id: int) -> None:
        now = time.time()
        with self._lock:
            recent = [
                timestamp
                for timestamp in self._requests[agent_id]
                if now - timestamp < self.window_seconds
            ]
            if len(recent) >= self.max_requests:
                self._requests[agent_id] = recent
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Trop de demandes de tickets WebSocket. Réessayez dans une minute.",
                )
            recent.append(now)
            self._requests[agent_id] = recent

    def reset(self) -> None:
        with self._lock:
            self._requests.clear()


websocket_ticket_rate_limiter = WebSocketTicketRateLimiter(max_requests=20, window_seconds=60)


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
    try:
        base32_secret = (
            decrypt_totp_secret_at_rest(encrypted_or_plain_secret)
            if encrypted_or_plain_secret.startswith("gAAAAA")
            else encrypted_or_plain_secret
        )
        totp = _build_pyca_totp(base32_secret)
        ts = int(timestamp if timestamp is not None else time.time())
        return totp.generate(ts).decode("utf-8")
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Impossible de déchiffrer la graine TOTP avec la clé Fernet active.",
        ) from exc


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

    # Demo accounts must never remain usable after switching a persistent database
    # from demo mode to production mode.
    if agent.is_demo_account and not DEMO_MODE_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Accès refusé : compte de démonstration désactivé hors mode démo.",
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


def require_account_manager(current_agent: EnrolledAgent = Depends(get_current_agent)) -> EnrolledAgent:
    """Allow account changes only to DGTD administrators and ministry focal points."""
    if current_agent.role not in ("SUPER_ADMIN_DGTD", "POINT_FOCAL"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="La gestion des comptes est réservée à la DGTD et aux points focaux.",
        )
    return current_agent


def require_super_admin(current_agent: EnrolledAgent = Depends(get_current_agent)) -> EnrolledAgent:
    """Only DGTD administrators may grant or revoke privileged roles."""
    if current_agent.role != "SUPER_ADMIN_DGTD":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cette opération est réservée à un administrateur DGTD.",
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
