"""Amorce le premier administrateur DGTD sur une base de production neuve.

À exécuter une seule fois par un opérateur de confiance, après le démarrage de
l'API pour que son schéma soit à jour. Cette commande n'expose aucun endpoint
public et refuse toute base contenant déjà un compte.
"""

import argparse
import secrets
import sys

import auth
from auth import (
    encrypt_totp_secret_at_rest,
    generate_totp_secret,
    get_timestamp_bucket,
    hash_password,
    pseudonymize_identifier,
)
from database import Base, SessionLocal, engine
from models import Channel, ChannelMember, EnrolledAgent, SecurityAuditLog
from provisioning import generate_activation_code
from seed import seed_institutional_channels


def bootstrap_initial_admin(
    db,
    *,
    matricule: str,
    full_name: str,
    ministry: str,
    direction: str,
    job_title: str,
) -> dict[str, str]:
    """Create a single pending DGTD account and return its one-time activation code."""
    if auth.DEMO_MODE_ENABLED:
        raise RuntimeError("L'amorçage de production est interdit en mode démo.")
    if db.query(EnrolledAgent).count() != 0:
        raise RuntimeError("Amorçage refusé : la base contient déjà des comptes.")

    matricule_clean = matricule.strip().upper()
    if not all((matricule_clean, full_name.strip(), ministry.strip(), direction.strip(), job_title.strip())):
        raise ValueError("Tous les champs d'identité sont obligatoires.")

    activation_code, activation_hash, activation_expiry = generate_activation_code()
    agent = EnrolledAgent(
        matricule=matricule_clean,
        full_name=full_name.strip(),
        ministry=ministry.strip(),
        direction=direction.strip(),
        job_title=job_title.strip(),
        role="SUPER_ADMIN_DGTD",
        preferred_lang="fr",
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
    db.add(agent)
    db.flush()

    seed_institutional_channels(db)
    default_channels = db.query(Channel).filter(
        (Channel.ministry_scope == "TOUS") | (Channel.ministry_scope == agent.ministry)
    ).all()
    for ch in default_channels:
        db.add(ChannelMember(channel_id=ch.id, agent_id=agent.id))

    db.add(
        SecurityAuditLog(
            event_type="INITIAL_SUPER_ADMIN_BOOTSTRAPPED",
            severity="WARNING",
            actor_pseudonym=pseudonymize_identifier(matricule_clean),
            description="Premier administrateur DGTD créé par amorçage opérateur hors API.",
            timestamp_bucket=get_timestamp_bucket(),
        )
    )
    db.commit()
    return {
        "matricule": matricule_clean,
        "activation_code": activation_code,
        "activation_expires_at": activation_expiry.isoformat() + "Z",
    }


def reissue_initial_admin_activation(db, matricule: str) -> dict[str, str]:
    """Recover the first-admin setup if its one-time activation flow was interrupted."""
    if auth.DEMO_MODE_ENABLED:
        raise RuntimeError("La réémission de production est interdite en mode démo.")
    agent = db.query(EnrolledAgent).filter(EnrolledAgent.matricule == matricule.strip().upper()).first()
    if not agent or agent.role != "SUPER_ADMIN_DGTD" or agent.is_enrolled_activated or agent.is_revoked:
        raise RuntimeError("Aucun administrateur DGTD en attente d'activation ne correspond à ce matricule.")

    code, code_hash, expires_at = generate_activation_code()
    agent.enrolment_token = code_hash
    agent.enrolment_token_expires_at = expires_at
    agent.totp_secret_encrypted = encrypt_totp_secret_at_rest(generate_totp_secret())
    agent.totp_enabled = False
    agent.token_version += 1
    db.add(
        SecurityAuditLog(
            event_type="INITIAL_SUPER_ADMIN_ACTIVATION_REISSUED",
            severity="WARNING",
            actor_pseudonym=pseudonymize_identifier(agent.matricule),
            description="Code d'activation initial DGTD réémis par un opérateur de confiance.",
            timestamp_bucket=get_timestamp_bucket(),
        )
    )
    db.commit()
    return {
        "matricule": agent.matricule,
        "activation_code": code,
        "activation_expires_at": expires_at.isoformat() + "Z",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Créer le premier administrateur DGTD sur une base neuve.")
    parser.add_argument("--matricule", required=True)
    parser.add_argument("--nom", dest="full_name")
    parser.add_argument("--ministere", dest="ministry")
    parser.add_argument("--direction")
    parser.add_argument("--fonction", dest="job_title")
    parser.add_argument(
        "--reissue-initial-admin",
        action="store_true",
        help="Réémettre le code d'un compte initial DGTD qui n'a pas terminé son activation.",
    )
    args = parser.parse_args()

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if args.reissue_initial_admin:
            credentials = reissue_initial_admin_activation(db, args.matricule)
        else:
            if not all((args.full_name, args.ministry, args.direction, args.job_title)):
                parser.error("--nom, --ministere, --direction et --fonction sont obligatoires pour créer le compte.")
            credentials = bootstrap_initial_admin(
                db,
                matricule=args.matricule,
                full_name=args.full_name,
                ministry=args.ministry,
                direction=args.direction,
                job_title=args.job_title,
            )
    except Exception as exc:
        db.rollback()
        print(f"Échec de l'amorçage : {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()

    print("Invitation initiale DGTD prête à être remise au titulaire.")
    print("Remettez le code ci-dessous au titulaire par un canal institutionnel sûr :")
    print(f"Matricule : {credentials['matricule']}")
    print(f"Code d'activation à usage unique (affiché une seule fois) : {credentials['activation_code']}")
    print(f"Expiration : {credentials['activation_expires_at']}")
    print("Le titulaire choisira son mot de passe et configurera son TOTP dans l'application.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
