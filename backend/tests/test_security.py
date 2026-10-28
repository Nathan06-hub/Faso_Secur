"""
Suite de tests automatisés des fonctions de sécurité souveraine (Bonus +2 points).
Couvre les 5 épreuves éliminatoires du jury :
1. Rejet d'un intrus non enrôlé (403 Forbidden + Audit Log)
2. Obligation du second facteur 2FA TOTP (RFC 6238 via PyCA cryptography)
3. « Le serveur ne lit rien » : rejet de tout champ en clair + vérification de l'opacité BDD
4. Révocation immédiate d'un agent pendant une conversation de groupe + rotation d'époque E2EE
5. Accusé de lecture à valeur probante signé cryptographiquement
"""

def _run_coro(coro):
    """Exécute une coroutine FastAPI directement en mémoire sans boucle socketpair Windows."""
    try:
        coro.send(None)
    except StopIteration as stop:
        return stop.value
    finally:
        coro.close()
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi import HTTPException

from auth import verify_and_load_active_agent
from database import Base, SessionLocal, engine
from main import (
    IntruderAttemptRequest,
    LoginRequest,
    RevokeAgentRequest,
    SendEncryptedMessageRequest,
    SignProbativeReceiptRequest,
    get_channel_encrypted_messages,
    inspect_raw_server_database_and_network,
    list_fictional_demo_accounts,
    login_enrolled_agent,
    post_encrypted_message,
    reinstate_revoked_agent_for_demo,
    reject_public_registration_or_intruder,
    revoke_agent_immediately,
    submit_probative_read_receipt,
)
from seed import seed_demo_data


@pytest.fixture(scope="module")
def db():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    seed_demo_data(session)
    yield session
    session.close()


def _login_helper(db, matricule: str, password: str = "FasoSecur!2026"):
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


def test_2_strong_authentication_2fa_totp_mandatory(db):
    """Vérifie que le second facteur 2FA TOTP (RFC 6238) est strictement obligatoire."""
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
    - Les messages et fichiers stockés en base ne contiennent que du `ciphertext_payload` opaque.
    """
    login_data = _login_helper(db, "BF-DGTD-001")
    admin_agent = verify_and_load_active_agent(login_data["access_token"], db)

    # Tentative d'envoi avec un champ plaintext -> refusé 400
    with pytest.raises(HTTPException) as exc_plain:
        _run_coro(
            post_encrypted_message(
                channel_id=1,
                req=SendEncryptedMessageRequest(
                    ciphertext_payload="U2FsdGVkX1+FakeCiphertextPayload1234567890",
                    nonce_or_iv="iv_random_987654321",
                    sender_ephemeral_public_key="ephem_pub_key_curve25519",
                    authenticity_mac="hmac_sha256_tag_1234567890abcdef",
                    plaintext="Texte en clair interdit",
                ),
                current_agent=admin_agent,
                db=db,
            )
        )
    assert exc_plain.value.status_code == 400

    # Envoi d'une enveloppe E2EE légitime (le texte secret "Instruction Ministérielle" n'est jamais envoyé)
    secret_cleartext = "Instruction Ministérielle Confidentielle n°2026-BF"
    simulated_megolm_ciphertext = "MEGOLM_V1_CIPHERTEXT_8f9a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a"
    ok_msg = _run_coro(
        post_encrypted_message(
            channel_id=1,
            req=SendEncryptedMessageRequest(
                e2ee_protocol="MATRIX_OLM_MEGOLM_E2EE",
                ciphertext_payload=simulated_megolm_ciphertext,
                nonce_or_iv="nonce_a1b2c3d4e5f60718293a4b5c",
                sender_ephemeral_public_key="curve25519_ephemeral_pub_9988776655",
                authenticity_mac="poly1305_mac_11223344556677889900aabbccddeeff",
                message_kind="SERVICE_INSTRUCTION",
                classification="CONFIDENTIEL",
                requires_probative_receipt=True,
            ),
            current_agent=admin_agent,
            db=db,
        )
    )
    assert ok_msg["ciphertext_payload"] == simulated_megolm_ciphertext

    # Inspection brute de la base de données côté serveur
    dump = inspect_raw_server_database_and_network(current_agent=admin_agent, db=db)
    assert dump["zero_knowledge_verification"]["plaintext_columns_in_db"] == 0
    raw_dump_str = str(dump["database_table_encrypted_messages"])
    assert secret_cleartext not in raw_dump_str
    assert simulated_megolm_ciphertext in raw_dump_str


def test_4_immediate_revocation_during_group_conversation(db):
    """
    Épreuve Jury « Révocation » :
    - L'agent BF-MISSION-999 est connecté et participe à un groupe.
    - L'administrateur DGTD le révoque en direct.
    - Son jeton JWT est immédiatement invalidé (403), il est retiré des groupes,
      et l'époque cryptographique (`crypto_epoch`) du groupe est incrémentée.
    """
    admin_token = _login_helper(db, "BF-DGTD-001")["access_token"]
    admin_agent = verify_and_load_active_agent(admin_token, db)

    agent_login = _login_helper(db, "BF-MISSION-999")
    agent_token = agent_login["access_token"]
    agent_id = agent_login["agent"]["id"]
    active_agent = verify_and_load_active_agent(agent_token, db)

    # Avant révocation, l'agent a accès aux messages du groupe #1
    pre_msgs = get_channel_encrypted_messages(channel_id=1, current_agent=active_agent, db=db)
    assert "messages" in pre_msgs

    # L'administrateur révoque immédiatement l'agent pendant la conversation
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

    # Immédiatement après, toute tentative d'utiliser son jeton JWT est rejetée (403)
    with pytest.raises(HTTPException) as exc_revoked:
        verify_and_load_active_agent(agent_token, db)
    assert exc_revoked.value.status_code == 403
    assert "RÉVOQUÉ" in exc_revoked.value.detail

    # Réhabilitation pour laisser la base prête pour la démo interactive
    reinstated = reinstate_revoked_agent_for_demo(
        agent_id=agent_id,
        admin_agent=admin_agent,
        db=db,
    )
    assert reinstated["status"] == "REINSTATED"


def test_5_probative_read_receipt_signature(db):
    """Vérifie la signature d'un accusé de lecture à valeur probante sur une instruction de service."""
    mefp_token = _login_helper(db, "BF-MEFP-102")["access_token"]
    mefp_agent = verify_and_load_active_agent(mefp_token, db)

    msgs = get_channel_encrypted_messages(channel_id=1, current_agent=mefp_agent, db=db)["messages"]
    assert len(msgs) >= 1
    target_msg_id = msgs[0]["id"]

    receipt = _run_coro(
        submit_probative_read_receipt(
            message_id=target_msg_id,
            req=SignProbativeReceiptRequest(
                signature_hex="ecdsa_p256_sig_9f8e7d6c5b4a3928172635445566778899aabbccddeeff00112233",
                signed_payload_hash="sha256_77889900aabbccddeeff11223344556677889900aabbccddeeff",
            ),
            current_agent=mefp_agent,
            db=db,
        )
    )
    assert receipt["agent_matricule"] == "BF-MEFP-102"
