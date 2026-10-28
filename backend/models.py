"""
Modèles SQLAlchemy pour FASO-SÉCUR (Serveur Souverain Zero-Knowledge).
Le serveur ne stocke JAMAIS de messages, sujets ou fichiers en clair.
Il stocke uniquement :
1. Les agents préalablement enrôlés (matricule, ministère, rôle, secret 2FA TOTP, statut de révocation)
2. Le trousseau de clés publiques E2EE (IdentityKey, SignedPreKey, OneTimePreKeys pour Olm/Signal)
3. Les salons/canaux institutionnels et leurs époques de session Megolm/MLS
4. Les enveloppes chiffrées de bout en bout (ciphertext, iv, ratchet_header, classification, expiration)
5. Les blobs chiffrés de pièces jointes et notes vocales E2EE
6. Les accusés de lecture signés à valeur probante
7. Le journal d'audit de sécurité (avec minimisation des métadonnées par hachage HMAC)
"""

from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
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
    # Clé publique d'identité Curve25519 / Ed25519 de l'agent (jamais la clé privée !)
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
    Le nom interne peut être pseudonymisé ; chaque révocation d'un membre incrémente `crypto_epoch`
    pour forcer la rotation immédiate de la session de groupe (Megolm / Sender Key).
    """
    __tablename__ = "channels"

    id = Column(Integer, primary_key=True, index=True)
    slug = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(128), nullable=False)
    ministry_scope = Column(String(128), nullable=False)  # ex: "TOUS", "MTDPCE", "MEFP", "DEFENSE"
    channel_type = Column(String(32), default="INSTITUTIONAL", nullable=False)  # INSTITUTIONAL, GROUP, DIRECT
    default_classification = Column(String(32), default="ORDINAIRE", nullable=False)
    crypto_epoch = Column(Integer, default=1, nullable=False)
    encrypted_group_session_bundles = Column(Text, nullable=True)  # Clés de session Megolm chiffrées par membre
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
    Enveloppe de message chiffrée de bout en bout (Zero-Knowledge).
    AUCUN champ en clair n'existe : le texte, les métadonnées de fichier et les notes vocales
    sont intégralement contenus dans `ciphertext_payload`.
    Les identifiants émetteur/canal sont stockés sous forme de pseudonymes HMAC pour minimiser les métadonnées.
    """
    __tablename__ = "encrypted_messages"

    id = Column(Integer, primary_key=True, index=True)
    channel_id = Column(Integer, ForeignKey("channels.id"), nullable=False, index=True)
    sender_id = Column(Integer, ForeignKey("enrolled_agents.id"), nullable=False)
    sender_pseudonym_hash = Column(String(64), nullable=False, index=True)

    # Protocole E2EE utilisé (ex: "MATRIX_MEGOLM_V1" ou "SIGNAL_DOUBLE_RATCHET_V1")
    e2ee_protocol = Column(String(64), default="MATRIX_OLM_MEGOLM_E2EE", nullable=False)
    crypto_epoch = Column(Integer, default=1, nullable=False)

    # Payload strictement chiffré (Base64 / JSON Olm-Megolm ciphertext)
    ciphertext_payload = Column(Text, nullable=False)
    nonce_or_iv = Column(String(128), nullable=False)
    sender_ephemeral_public_key = Column(Text, nullable=False)
    authenticity_mac = Column(String(256), nullable=False)

    # Type d'enveloppe E2EE : TEXT, VOICE_NOTE, ATTACHMENT, SERVICE_INSTRUCTION
    message_kind = Column(String(32), default="TEXT", nullable=False)

    # Classification administrative : ORDINAIRE, DIFFUSION_RESTREINTE, CONFIDENTIEL
    classification = Column(String(32), default="ORDINAIRE", nullable=False)
    no_forward = Column(Boolean, default=False, nullable=False)
    anti_screenshot = Column(Boolean, default=False, nullable=False)
    requires_probative_receipt = Column(Boolean, default=False, nullable=False)
    expires_at = Column(DateTime, nullable=True)

    # Référence optionnelle vers un blob binaire chiffré (fichier / note vocale E2EE)
    encrypted_blob_id = Column(String(64), nullable=True)

    # Horodatage arrondi à la minute (minimisation des métadonnées temporelles)
    timestamp_bucket = Column(String(32), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class EncryptedAttachmentBlob(Base):
    """
    Stockage souverain de fichiers et notes vocales chiffrés de bout en bout.
    Le serveur ne connaît même pas le nom original ni le type MIME en clair du fichier :
    tout est chiffré côté client avant upload.
    """
    __tablename__ = "encrypted_attachment_blobs"

    blob_id = Column(String(64), primary_key=True, index=True)
    channel_id = Column(Integer, ForeignKey("channels.id"), nullable=False)
    uploader_pseudonym_hash = Column(String(64), nullable=False)
    ciphertext_b64 = Column(Text, nullable=False)
    iv_b64 = Column(String(128), nullable=False)
    sha256_ciphertext = Column(String(128), nullable=False)
    size_padded_bytes = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class ProbativeReadReceipt(Base):
    """
    Accusé de lecture à valeur probante pour les instructions de service officielles.
    Contient la signature cryptographique Ed25519/ECDSA générée par la clé privée de l'agent lecteur
    sur le condensat (hash) du message chiffré et l'horodatage.
    """
    __tablename__ = "probative_read_receipts"

    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(Integer, ForeignKey("encrypted_messages.id"), nullable=False, index=True)
    agent_id = Column(Integer, ForeignKey("enrolled_agents.id"), nullable=False)
    agent_matricule = Column(String(64), nullable=False)
    agent_full_name = Column(String(128), nullable=False)
    signature_hex = Column(Text, nullable=False)
    signed_payload_hash = Column(String(128), nullable=False)
    signed_at = Column(DateTime, default=utcnow, nullable=False)


class SecurityAuditLog(Base):
    """
    Journal d'audit de sécurité immuable avec minimisation des métadonnées.
    Enregistre les tentatives d'intrusion, les révocations d'agents, les rotations de clés E2EE
    et les vérifications 2FA.
    """
    __tablename__ = "security_audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(64), nullable=False, index=True)  # INTRUSION_BLOCKED, AGENT_REVOKED, KEY_ROTATION, LOGIN_2FA_OK
    severity = Column(String(32), default="INFO", nullable=False)  # INFO, WARNING, CRITICAL
    actor_pseudonym = Column(String(128), nullable=False)
    description = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
