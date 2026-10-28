"""
Initialisation des données fictives de démonstration pour le jury du Hackathon 226.
Conformément aux règles du sprint :
- Seules des données et des comptes fictifs sont utilisés.
- Ces comptes permettent au jury de tester immédiatement l'échange chiffré E2EE,
  la révocation en direct d'un agent pendant une conversation de groupe, le rejet d'un intrus,
  et les fonctionnalités innovantes (classification, accusés probants, langues nationales).
"""

from sqlalchemy.orm import Session
from auth import encrypt_totp_secret_at_rest, get_timestamp_bucket, hash_password, pseudonymize_identifier
from models import Channel, ChannelMember, EnrolledAgent, SecurityAuditLog

DEMO_AGENTS = [
    {
        "matricule": "BF-DGTD-001",
        "full_name": "Aminata OUÉDRAOGO (Fictif)",
        "ministry": "MTDPCE (Transition Digitale & Postes)",
        "direction": "DGTD — Direction de la Sécurité Souveraine",
        "job_title": "Administratrice Principale de la Messagerie d'État",
        "role": "SUPER_ADMIN_DGTD",
        "preferred_lang": "fr",
        "password": "FasoSecur!2026",
        "totp_secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXA",
    },
    {
        "matricule": "BF-MEFP-102",
        "full_name": "Ibrahim SAWADOGO (Fictif)",
        "ministry": "MEFP (Économie, Finances et Prospective)",
        "direction": "Direction Générale du Trésor et de la Comptabilité Publique",
        "job_title": "Point Focal Ministériel & Inspecteur",
        "role": "POINT_FOCAL",
        "preferred_lang": "moore",
        "password": "FasoSecur!2026",
        "totp_secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXB",
    },
    {
        "matricule": "BF-MATDS-204",
        "full_name": "Moussa KABORÉ (Fictif)",
        "ministry": "MATDS (Administration Territoriale & Sécurité)",
        "direction": "Direction Générale de l'Administration du Territoire",
        "job_title": "Chargé des Transmissions Régionales",
        "role": "AGENT_PUBLIC",
        "preferred_lang": "dioula",
        "password": "FasoSecur!2026",
        "totp_secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXC",
    },
    {
        "matricule": "BF-SANTE-308",
        "full_name": "Fatimata DIALLO (Fictif)",
        "ministry": "MSHP (Santé et Hygiène Publique)",
        "direction": "Direction des Urgences et de la Logistique Sanitaire",
        "job_title": "Coordonnatrice Nationale",
        "role": "AGENT_PUBLIC",
        "preferred_lang": "fulfulde",
        "password": "FasoSecur!2026",
        "totp_secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXD",
    },
    {
        "matricule": "BF-MISSION-999",
        "full_name": "Adama ZONGO (Fictif - Test Révocation)",
        "ministry": "MTDPCE (Transition Digitale & Postes)",
        "direction": "Mission Temporaire Interministérielle",
        "job_title": "Agent en détachement (Compte de test pour Révocation Jury)",
        "role": "AGENT_PUBLIC",
        "preferred_lang": "fr",
        "password": "FasoSecur!2026",
        "totp_secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXE",
    },
]

DEMO_CHANNELS = [
    {
        "slug": "coordination-interministerielle",
        "name": "Coordination Interministérielle (SG / DGTD / MEFP)",
        "ministry_scope": "TOUS",
        "channel_type": "INSTITUTIONAL",
        "default_classification": "DIFFUSION_RESTREINTE",
    },
    {
        "slug": "cellule-veille-souveraine",
        "name": "Cellule Nationale de Veille & Instructions Officielles",
        "ministry_scope": "TOUS",
        "channel_type": "GROUP",
        "default_classification": "CONFIDENTIEL",
    },
    {
        "slug": "mtdpce-dgtd-interne",
        "name": "MTDPCE — Direction Générale de la Transformation Digitale",
        "ministry_scope": "MTDPCE (Transition Digitale & Postes)",
        "channel_type": "INSTITUTIONAL",
        "default_classification": "ORDINAIRE",
    },
    {
        "slug": "canal-terrain-regions",
        "name": "Relais Régions & Zones à Faible Couverture (Mooré/Dioula/Fulfulde)",
        "ministry_scope": "TOUS",
        "channel_type": "GROUP",
        "default_classification": "ORDINAIRE",
    },
]


def seed_demo_data(db: Session) -> None:
    """Insère les agents fictifs enrôlés et les canaux institutionnels s'ils n'existent pas encore."""
    existing_count = db.query(EnrolledAgent).count()
    if existing_count > 0:
        return

    created_agents = []
    for item in DEMO_AGENTS:
        agent = EnrolledAgent(
            matricule=item["matricule"],
            full_name=item["full_name"],
            ministry=item["ministry"],
            direction=item["direction"],
            job_title=item["job_title"],
            role=item["role"],
            preferred_lang=item["preferred_lang"],
            password_hash=hash_password(item["password"]),
            totp_secret_encrypted=encrypt_totp_secret_at_rest(item["totp_secret"]),
            totp_enabled=True,
            is_enrolled_activated=True,
            is_revoked=False,
            token_version=1,
        )
        db.add(agent)
        created_agents.append(agent)

    db.flush()

    created_channels = []
    for ch in DEMO_CHANNELS:
        channel = Channel(
            slug=ch["slug"],
            name=ch["name"],
            ministry_scope=ch["ministry_scope"],
            channel_type=ch["channel_type"],
            default_classification=ch["default_classification"],
            crypto_epoch=1,
        )
        db.add(channel)
        created_channels.append(channel)

    db.flush()

    # Inscrire les agents enrôlés aux canaux correspondant à leur ministère (ou interministériels 'TOUS')
    for channel in created_channels:
        for agent in created_agents:
            if channel.ministry_scope == "TOUS" or channel.ministry_scope == agent.ministry:
                db.add(ChannelMember(channel_id=channel.id, agent_id=agent.id))

    db.add(
        SecurityAuditLog(
            event_type="SOVEREIGN_NODE_BOOTSTRAPPED",
            severity="INFO",
            actor_pseudonym=pseudonymize_identifier("BF-DGTD-001"),
            description=(
                "Initialisation souveraine FASO-SÉCUR : 5 agents fictifs enrôlés avec 2FA TOTP (RFC 6238) "
                "et 4 canaux institutionnels E2EE activés."
            ),
            timestamp_bucket=get_timestamp_bucket(),
        )
    )
    db.commit()
