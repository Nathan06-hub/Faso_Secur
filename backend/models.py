"""
Modèles SQLAlchemy pour FASO-SÉCUR (Serveur Souverain Zero-Knowledge & Sealed Sender).
Le serveur ne stocke JAMAIS de messages, sujets ou fichiers en clair.
Conformément à l'architecture Sealed Sender :
1. Aucune clé étrangère `sender_id` en clair ni horodatage à la milliseconde n'est stocké
   dans `encrypted_messages` (uniquement `sender_pseudonym_hash` HMAC-SHA256 et `timestamp_bucket` 5 min).
2. L'identité de l'émetteur, le texte, la classification et les métadonnées de fichier sont
   encapsulés dans `ciphertext_payload` (AES-256-GCM) et signés par `ECDSA P-256`.
"""

from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from database import Base


def utcnow():
    return datetime.now(timezone.utc)


class EnrolledAgent(Base):
    """
    Agent public préalablement enrôlé par la DGTD ou le Point Focal Ministériel.
    Un individu non présent dans cette table ne peut PAS créer de compte ni se connecter (Rejet d'intrus).
    """
    __tablename__ = "enrolled_agents"

    id = Column(Integer, primary_key=True, index=True)
    matricule = Column(String(64), unique=True, index=True, nullable=False)
    full_name = Column(String(128), nullable=False)
    ministry = Column(String(128), nullable=False)
    direction = Column(String(128), nullable=False)
    job_title = Column(String(128), nullable=False)
    role = Column(String(32), default="AGENT_PUBLIC", nullable=False)  # SUPER_ADMIN_DGTD, POINT_FOCAL, AGENT_PUBLIC, AUDITEUR
    preferred_lang = Column(String(16), default="fr", nullable=False)  # fr, moore, dioula, fulfulde

    # Authentification forte (Mot de passe haché bcrypt + Secret 2FA TOTP RFC 6238)
    password_hash = Column(String(256), nullable=False)
    totp_secret = Column(String(64), nullable=False)
    totp_enabled = Column(Boolean, default=True, nullable=False)
    enrolment_token = Column(String(128), nullable=True)
    is_enrolled_activated = Column(Boolean, default=True, nullable=False)

    # Statut de révocation immédiate
    is_revoked = Column(Boolean, default=False, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    revocation_reason = Column(String(256), nullable=True)
    token_version = Column(Integer, default=1, nullable=False)

    # Trousseau de clés publiques E2EE (Protocole Matrix Olm/Megolm & Signal X3DH)
    # Clé publique d'identité ECDH P-256 et clé publique de signature ECDSA P-256 (jamais la clé privée !)
    e2ee_identity_public_key = Column(Text, nullable=True)
    e2ee_signing_public_key = Column(Text, nullable=True)
    e2ee_signed_prekey_public = Column(Text, nullable=True)
    e2ee_signed_prekey_signature = Column(Text, nullable=True)
    e2ee_one_time_prekeys_json = Column(Text, nullable=True)
    e2ee_key_epoch = Column(Integer, default=1, nullable=False)

    created_at = Column(DateTime, default=utcnow, nullable=False)


class Channel(Base):
    """
    Canal institutionnel ou conversation de groupe / directe.
    Chaque révocation d'un membre incrémente `crypto_epoch` et renouvelle les enveloppes
    de clés de session de groupe chiffrées par ECDH (`encrypted_group_session_bundles`).
    """
    __tablename__ = "channels"

    id = Column(Integer, primary_key=True, index=True)
    slug = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(128), nullable=False)
    ministry_scope = Column(String(128), nullable=False)
    channel_type = Column(String(32), default="INSTITUTIONAL", nullable=False)
    default_classification = Column(String(32), default="ORDINAIRE", nullable=False)
    crypto_epoch = Column(Integer, default=1, nullable=False)
    # Dictionnaire JSON { "<epoch>": { "<matricule>": { ephemeralPubJwk, ivB64, wrappedKeyB64 } } }
    encrypted_group_session_bundles = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class ChannelMember(Base):
    """Association d'un agent enrôlé à un canal ou groupe de discussion."""
    __tablename__ = "channel_members"

    id = Column(Integer, primary_key=True, index=True)
    channel_id = Column(Integer, ForeignKey("channels.id"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("enrolled_agents.id"), nullable=False, index=True)
    joined_at = Column(DateTime, default=utcnow, nullable=False)


class EncryptedMessage(Base):
    """
    Enveloppe de message chiffrée de bout en bout avec Sealed Sender (Zero-Knowledge).
    Minimisation stricte des métadonnées :
    - PAS de `sender_id` en clair (uniquement `sender_pseudonym_hash` HMAC-SHA256)
    - PAS de `created_at` à la milliseconde (uniquement `timestamp_bucket` arrondi à 5 minutes)
    - L'identité de l'émetteur, le texte et les métadonnées sont chiffrés dans `ciphertext_payload`.
    """
    __tablename__ = "encrypted_messages"

    id = Column(Integer, primary_key=True, index=True)
    channel_id = Column(Integer, ForeignKey("channels.id"), nullable=False, index=True)
    sender_pseudonym_hash = Column(String(64), nullable=False, index=True)

    # Protocole E2EE utilisé (ex: "MATRIX_MEGOLM_X3DH_ECDH_V2")
    e2ee_protocol = Column(String(64), default="MATRIX_OLM_MEGOLM_X3DH_V2", nullable=False)
    crypto_epoch = Column(Integer, default=1, nullable=False)

    # Payload strictement chiffré (Base64 AES-256-GCM contenant texte + Sealed Sender + métadonnées)
    ciphertext_payload = Column(Text, nullable=False)
    nonce_or_iv = Column(String(128), nullable=False)
    sender_ephemeral_public_key = Column(Text, nullable=False)
    authenticity_mac = Column(String(256), nullable=False)
    ecdsa_verified_by_server = Column(Boolean, default=True, nullable=False)

    # Métadonnées scellées (masquées en BDD sous "SEALED_E2EE" par défaut ou règles de rétention)
    message_kind = Column(String(32), default="SEALED_E2EE", nullable=False)
    classification = Column(String(32), default="SEALED_E2EE", nullable=False)
    no_forward = Column(Boolean, default=False, nullable=False)
    anti_screenshot = Column(Boolean, default=False, nullable=False)
    requires_probative_receipt = Column(Boolean, default=False, nullable=False)
    expires_at = Column(DateTime, nullable=True)

    # Référence optionnelle vers un blob binaire chiffré (fichier / note vocale E2EE)
    encrypted_blob_id = Column(String(64), nullable=True)

    # Horodatage strictement arrondi par tranche de 5 minutes (aucun timestamp milliseconde)
    timestamp_bucket = Column(String(32), nullable=False)


class EncryptedAttachmentBlob(Base):
    """
    Stockage souverain de fichiers et notes vocales chiffrés de bout en bout.
    Le serveur ne connaît ni le nom original ni le type MIME en clair du fichier.
    """
    __tablename__ = "encrypted_attachment_blobs"

    blob_id = Column(String(64), primary_key=True, index=True)
    channel_id = Column(Integer, ForeignKey("channels.id"), nullable=False)
    uploader_pseudonym_hash = Column(String(64), nullable=False)
    ciphertext_b64 = Column(Text, nullable=False)
    iv_b64 = Column(String(128), nullable=False)
    sha256_ciphertext = Column(String(128), nullable=False)
    size_padded_bytes = Column(Integer, nullable=False)
    timestamp_bucket = Column(String(32), nullable=False)


class ProbativeReadReceipt(Base):
    """
    Accusé de lecture à valeur probante pour les instructions de service officielles.
    Contient la signature cryptographique ECDSA P-256 vérifiée par le serveur et les pairs.
    """
    __tablename__ = "probative_read_receipts"

    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(Integer, ForeignKey("encrypted_messages.id"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("enrolled_agents.id"), nullable=False)
    agent_matricule = Column(String(64), nullable=False)
    agent_full_name = Column(String(128), nullable=False)
    signature_hex = Column(Text, nullable=False)
    signed_payload_hash = Column(String(128), nullable=False)
    ecdsa_verified = Column(Boolean, default=True, nullable=False)
    signed_at = Column(DateTime, default=utcnow, nullable=False)


class SecurityAuditLog(Base):
    """
    Journal d'audit de sécurité immuable avec minimisation des métadonnées.
    """
    __tablename__ = "security_audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), default="INFO", nullable=False)
    actor_pseudonym = Column(String(128), nullable=False)
    description = Column(Text, nullable=False)
    timestamp_bucket = Column(String(32), nullable=False)
