"""
Suite de tests automatisés des fonctions de sécurité souveraine (Bonus +2 points).
Couvre les 5 épreuves éliminatoires du jury + l'ensemble des exigences du Ré-Audit Technique :
1. Rejet d'un intrus non enrôlé (403 Forbidden + Audit Log)
2. Obligation du second facteur 2FA TOTP (RFC 6238 via PyCA cryptography) + Chiffrement Fernet au repos
3. « Le serveur ne lit rien » : rejet de tout champ en clair + vérification dynamique de l'opacité BDD + RBAC sur l'inspecteur
4. Révocation immédiate d'un agent pendant une conversation de groupe + rotation d'époque E2EE + restauration exacte des canaux d'origine
5. Accusé de lecture à valeur probante signé cryptographiquement (ECDSA P-256 vérifié contre l'annuaire)
6. Vérification mathématique obligatoire des signatures ECDSA P-256 contre la clé d'annuaire et rejet de toute falsification
7. Architecture Sealed Sender (zéro sender_id / no_forward / anti_screenshot / sender_ephemeral_public_key en clair) & Anti-Brute-Force (HTTP 429)
"""

import base64
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi import HTTPException

import auth
import main
from auth import login_rate_limiter, require_admin_role, verify_and_load_active_agent
from database import Base, SessionLocal, engine
from main import (
    IntruderAttemptRequest,
    LoginRequest,
    PublishPublicKeysRequest,
    RevokeAgentRequest,
    SendEncryptedMessageRequest,
    SignProbativeReceiptRequest,
    get_channel_encrypted_messages,
    inspect_raw_server_database_and_network,
    list_agent_channels,
    list_fictional_demo_accounts,
    login_enrolled_agent,
    post_encrypted_message,
    publish_agent_public_key_bundle,
    reinstate_revoked_agent_for_demo,
    reject_public_registration_or_intruder,
    revoke_agent_immediately,
    submit_probative_read_receipt,
)
from models import EnrolledAgent
from seed import seed_demo_data


def _run_coro(coro):
    """Exécute une coroutine FastAPI directement en mémoire sans boucle socketpair Windows."""
    try:
        coro.send(None)
    except StopIteration as stop:
        return stop.value
    finally:
        coro.close()


def _int_to_b64url(val: int) -> str:
    raw = val.to_bytes(32, byteorder="big")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _generate_ecdsa_p256_keypair_and_jwk():
    priv_key = ec.generate_private_key(ec.SECP256R1())
    pub_numbers = priv_key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _int_to_b64url(pub_numbers.x),
        "y": _int_to_b64url(pub_numbers.y),
    }
    return priv_key, json.dumps(jwk)


def _sign_p1363_hex(priv_key, data_bytes: bytes) -> str:
    der_sig = priv_key.sign(data_bytes, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    p1363_bytes = r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")
    return p1363_bytes.hex()


def _publish_test_keys_for_agent(db, agent):
    signing_priv, signing_pub_jwk = _generate_ecdsa_p256_keypair_and_jwk()
    _, id_pub_jwk = _generate_ecdsa_p256_keypair_and_jwk()
    valid_prekey_sig = _sign_p1363_hex(signing_priv, id_pub_jwk.encode("utf-8"))
    res = publish_agent_public_key_bundle(
        req=PublishPublicKeysRequest(
            identity_public_key=id_pub_jwk,
            signing_public_key=signing_pub_jwk,
            signed_prekey_public=id_pub_jwk,
            signed_prekey_signature=valid_prekey_sig,
        ),
        current_agent=agent,
        db=db,
    )
    assert res["status"] == "PUBLIC_KEYS_PUBLISHED_AND_VERIFIED"
    assert len(res["e2ee_safety_number"]) >= 30
    return signing_priv, signing_pub_jwk


@pytest.fixture(scope="module")
def db():
    auth.DEMO_MODE_ENABLED = True
    main.DEMO_MODE_ENABLED = True
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    seed_demo_data(session)
    yield session
    session.close()


def _login_helper(db, matricule: str, password: str = "FasoSecur!2026"):
    login_rate_limiter.reset(matricule)
    accounts = {
        a["matricule"]: a
        for a in list_fictional_demo_accounts(db=db)["demo_accounts"]
    }
    totp_code = accounts[matricule]["current_totp_code"]
    return login_enrolled_agent(
        LoginRequest(matricule=matricule, password=password, totp_code=totp_code),
        db=db,
    )


def test_1_intruder_rejected_and_logged(db):
    """Épreuve Jury « Intrus » : un compte non enrôlé tente de rejoindre la messagerie -> rejet 403."""
    with pytest.raises(HTTPException) as exc_login:
        login_enrolled_agent(
            LoginRequest(
                matricule="BF-INTRUS-9999",
                password="HackerPassword123",
                totp_code="123456",
            ),
            db=db,
        )
    assert exc_login.value.status_code == 403
    assert "INTRUS REJETÉ" in exc_login.value.detail

    with pytest.raises(HTTPException) as exc_reg:
        reject_public_registration_or_intruder(
            IntruderAttemptRequest(
                matricule="EXTERNE-007",
                full_name="Intrus Externe",
                target_channel_slug="cellule-veille-souveraine",
            ),
            db=db,
        )
    assert exc_reg.value.status_code == 403
    assert "REJET SÉCURITÉ SOUVERAINE" in exc_reg.value.detail


def test_2_strong_authentication_2fa_totp_mandatory_and_fernet_encrypted_at_rest(db):
    """
    Vérifie que :
    1. Le second facteur 2FA TOTP (RFC 6238) est strictement obligatoire.
    2. Les secrets TOTP sont chiffrés au repos via Fernet (`gAAAAA...`) en base de données (aucun secret en clair).
    """
    all_agents = db.query(EnrolledAgent).all()
    assert len(all_agents) >= 5
    for ag in all_agents:
        assert ag.totp_secret_encrypted.startswith("gAAAAA")

    with pytest.raises(HTTPException) as exc_bad_2fa:
        login_enrolled_agent(
            LoginRequest(
                matricule="BF-DGTD-001",
                password="FasoSecur!2026",
                totp_code="000000",
            ),
            db=db,
        )
    assert exc_bad_2fa.value.status_code == 401
    assert "2FA TOTP" in exc_bad_2fa.value.detail

    ok_data = _login_helper(db, "BF-DGTD-001")
    assert "access_token" in ok_data
    assert ok_data["agent"]["role"] == "SUPER_ADMIN_DGTD"


def test_3_server_reads_nothing_e2ee_and_blocks_plaintext(db):
    """
    Épreuve Jury « Le serveur ne lit rien » :
    - Toute tentative d'envoyer un message en clair (`plaintext`) est bloquée (400).
    - Signature ECDSA P-256 vérifiée contre la clé d'annuaire (`e2ee_signing_public_key`) obligatoire.
    - Les messages et fichiers stockés en base ne contiennent que du `ciphertext_payload` opaque.
    - L'endpoint `/api/jury/server-inspection` est protégé par RBAC (interdit aux simples agents).
    """
    login_data = _login_helper(db, "BF-DGTD-001")
    admin_agent = verify_and_load_active_agent(login_data["access_token"], db)
    admin_priv_key, _ = _publish_test_keys_for_agent(db, admin_agent)

    # Tentative d'envoi avec un champ plaintext -> refusé 400
    with pytest.raises(HTTPException) as exc_plain:
        _run_coro(
            post_encrypted_message(
                channel_id=1,
                req=SendEncryptedMessageRequest(
                    ciphertext_payload="U2FsdGVkX1+FakeCiphertextPayload1234567890",
                    nonce_or_iv="iv_random_987654321",
                    authenticity_mac="00" * 64,
                    plaintext="Texte en clair interdit",
                ),
                current_agent=admin_agent,
                db=db,
            )
        )
    assert exc_plain.value.status_code == 400

    # Envoi d'une enveloppe E2EE légitime signée ECDSA P-256 (le texte secret n'est jamais envoyé)
    secret_cleartext = "Instruction Ministérielle Confidentielle n°2026-BF"
    simulated_ciphertext = base64.b64encode(b"WEBCRYPTO_AES256GCM_CIPHERTEXT_8f9a2b3c4d5e6f7a8b9c0d1e2f3a4b5c").decode("ascii")
    nonce_val = base64.b64encode(b"123456789012").decode("ascii")
    signed_data = f"1:1:{nonce_val}:{simulated_ciphertext}".encode("utf-8")
    valid_sig_hex = _sign_p1363_hex(admin_priv_key, signed_data)

    ok_msg = _run_coro(
        post_encrypted_message(
            channel_id=1,
            req=SendEncryptedMessageRequest(
                e2ee_protocol="WEBCRYPTO_ECDH_HKDF_AES256GCM_ECDSA",
                ciphertext_payload=simulated_ciphertext,
                nonce_or_iv=nonce_val,
                authenticity_mac=valid_sig_hex,
                requires_probative_receipt=True,
            ),
            current_agent=admin_agent,
            db=db,
        )
    )
    assert ok_msg["ciphertext_payload"] == simulated_ciphertext
    assert ok_msg["ecdsa_verified_by_server"] is True

    # Vérification RBAC : un simple agent public ne peut pas accéder à l'inspecteur BDD
    sante_token = _login_helper(db, "BF-SANTE-308")["access_token"]
    sante_agent = verify_and_load_active_agent(sante_token, db)
    with pytest.raises(HTTPException) as exc_rbac:
        require_admin_role(sante_agent)
    assert exc_rbac.value.status_code == 403

    # Inspection brute de la base de données côté serveur (par l'administrateur DGTD)
    dump = inspect_raw_server_database_and_network(admin_agent=admin_agent, db=db)
    assert dump["zero_knowledge_verification"]["plaintext_columns_in_db"] == 0
    assert dump["zero_knowledge_verification"]["all_payloads_encrypted"] is True
    assert dump["zero_knowledge_verification"]["all_totp_secrets_fernet_encrypted_at_rest"] is True
    assert dump["zero_knowledge_verification"]["sealed_sender_active"] is True
    raw_dump_str = str(dump["database_table_encrypted_messages"])
    assert secret_cleartext not in raw_dump_str
    assert simulated_ciphertext in raw_dump_str


def test_4_immediate_revocation_during_group_conversation(db):
    """
    Épreuve Jury « Révocation » :
    - L'agent BF-SANTE-308 (ou BF-MISSION-999) est connecté et participe à des canaux spécifiques.
    - L'administrateur DGTD le révoque en direct.
    - Son jeton JWT est immédiatement invalidé (403), il est retiré des canaux,
      et l'époque cryptographique (`crypto_epoch`) du groupe est incrémentée.
    - Lors de la réhabilitation de démo, il ne retrouve QUE ses canaux initiaux (et non tous les canaux).
    """
    admin_token = _login_helper(db, "BF-DGTD-001")["access_token"]
    admin_agent = verify_and_load_active_agent(admin_token, db)

    agent_login = _login_helper(db, "BF-SANTE-308")
    agent_token = agent_login["access_token"]
    agent_id = agent_login["agent"]["id"]
    active_agent = verify_and_load_active_agent(agent_token, db)

    before_channels = [c["id"] for c in list_agent_channels(current_agent=active_agent, db=db)["channels"]]
    assert before_channels == [1, 2, 4]  # Ne fait pas partie du canal 3 interne MTDPCE

    revoke_data = _run_coro(
        revoke_agent_immediately(
            agent_id=agent_id,
            req=RevokeAgentRequest(reason="Révocation en direct par le jury (perte de téléphone)"),
            admin_agent=admin_agent,
            db=db,
        )
    )
    assert revoke_data["status"] == "REVOKED_IMMEDIATELY"
    assert revoke_data["rotated_channels_epochs"][1] >= 2

    with pytest.raises(HTTPException) as exc_revoked:
        verify_and_load_active_agent(agent_token, db)
    assert exc_revoked.value.status_code == 403
    assert "RÉVOQUÉ" in exc_revoked.value.detail

    # Si DEMO_MODE est désactivé en production, la réhabilitation est interdite (403)
    auth.DEMO_MODE_ENABLED = False
    with pytest.raises(HTTPException) as exc_prod:
        reinstate_revoked_agent_for_demo(agent_id=agent_id, admin_agent=admin_agent, db=db)
    assert exc_prod.value.status_code == 403
    auth.DEMO_MODE_ENABLED = True

    reinstated = reinstate_revoked_agent_for_demo(
        agent_id=agent_id,
        admin_agent=admin_agent,
        db=db,
    )
    assert reinstated["status"] == "REINSTATED"
    assert reinstated["restored_channels"] == [1, 2, 4]


def test_5_probative_read_receipt_signature(db):
    """Vérifie la signature ECDSA P-256 obligatoire d'un accusé de lecture à valeur probante."""
    mefp_token = _login_helper(db, "BF-MEFP-102")["access_token"]
    mefp_agent = verify_and_load_active_agent(mefp_token, db)
    mefp_priv_key, _ = _publish_test_keys_for_agent(db, mefp_agent)

    msgs = get_channel_encrypted_messages(channel_id=1, current_agent=mefp_agent, db=db)["messages"]
    assert len(msgs) >= 1
    target_msg = msgs[0]
    target_msg_id = target_msg["id"]

    # Calcul du hash SHA-256 du message et signature ECDSA P-256 réelle sur les 32 octets du condensat
    payload_to_hash = (
        f"PROBATIVE_RECEIPT::MSG={target_msg_id}::AGENT=BF-MEFP-102::CIPHER={target_msg['ciphertext_payload']}"
    ).encode("utf-8")
    digest_hex = hashlib.sha256(payload_to_hash).hexdigest()
    sig_hex = _sign_p1363_hex(mefp_priv_key, bytes.fromhex(digest_hex))

    receipt = _run_coro(
        submit_probative_read_receipt(
            message_id=target_msg_id,
            req=SignProbativeReceiptRequest(
                signature_hex=sig_hex,
                signed_payload_hash=digest_hex,
            ),
            current_agent=mefp_agent,
            db=db,
        )
    )
    assert receipt["agent_matricule"] == "BF-MEFP-102"
    assert receipt["ecdsa_verified"] is True


def test_6_ecdsa_p256_jwk_signature_verification_and_tamper_rejection(db):
    """
    Vérifie que le serveur valide mathématiquement les signatures ECDSA P-256 (format IEEE P1363 WebCrypto)
    contre la clé publique certifiée dans l'annuaire et rejette toute falsification (400).
    """
    matds_token = _login_helper(db, "BF-MATDS-204")["access_token"]
    matds_agent = verify_and_load_active_agent(matds_token, db)
    _publish_test_keys_for_agent(db, matds_agent)

    # Envoi d'un message avec une signature ECDSA P-256 falsifiée -> rejeté 400
    with pytest.raises(HTTPException) as exc_bad_sig:
        _run_coro(
            post_encrypted_message(
                channel_id=1,
                req=SendEncryptedMessageRequest(
                    ciphertext_payload="CIPHERTEXT_AUTHENTICATED_PAYLOAD_998877",
                    nonce_or_iv="iv_1234567890",
                    authenticity_mac="00" * 64,
                ),
                current_agent=matds_agent,
                db=db,
            )
        )
    assert exc_bad_sig.value.status_code == 400
    assert "REJET CRYPTOGRAPHIQUE" in exc_bad_sig.value.detail


def test_7_sealed_sender_zero_metadata_and_brute_force_lockout(db):
    """
    1. Vérifie que `encrypted_messages` ne contient aucun `sender_id`, `created_at`,
       `sender_ephemeral_public_key`, `no_forward` ou `anti_screenshot` en clair.
    2. Vérifie que 5 tentatives de connexion échouées déclenchent le verrouillage anti-brute-force (HTTP 429).
    """
    admin_token = _login_helper(db, "BF-DGTD-001")["access_token"]
    admin_agent = verify_and_load_active_agent(admin_token, db)
    dump = inspect_raw_server_database_and_network(admin_agent=admin_agent, db=db)

    for row in dump["database_table_encrypted_messages"]:
        assert "sender_id" not in row
        assert "created_at" not in row
        assert "sender_ephemeral_public_key" not in row
        assert "no_forward" not in row
        assert "anti_screenshot" not in row
        assert row["classification"] == "SEALED_E2EE"
        assert row["message_kind"] == "SEALED_E2EE"

    # Test du Rate Limiting Brute-Force (5 échecs -> 429 Too Many Requests)
    target_matricule = "BF-SANTE-308"
    login_rate_limiter.reset(target_matricule)
    for _ in range(5):
        with pytest.raises(HTTPException) as exc_fail:
            login_enrolled_agent(
                LoginRequest(
                    matricule=target_matricule,
                    password="WrongPassword!",
                    totp_code="000000",
                ),
                db=db,
            )
        assert exc_fail.value.status_code == 401

    with pytest.raises(HTTPException) as exc_lockout:
        login_enrolled_agent(
            LoginRequest(
                matricule=target_matricule,
                password="FasoSecur!2026",
                totp_code="000000",
            ),
            db=db,
        )
    assert exc_lockout.value.status_code == 429
    assert "ANTI-BRUTE-FORCE" in exc_lockout.value.detail
    login_rate_limiter.reset(target_matricule)
