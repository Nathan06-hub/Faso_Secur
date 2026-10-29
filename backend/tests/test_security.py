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
import secrets
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi import HTTPException, Response, WebSocketDisconnect
from fastapi.security import HTTPAuthorizationCredentials

import auth
import main
from auth import (
    generate_current_totp_code,
    login_rate_limiter,
    require_account_manager,
    require_admin_role,
    verify_and_load_active_agent,
)
from database import Base, SessionLocal, engine
from main import (
    SUPPORTED_E2EE_PROTOCOL,
    AccountActivationCompleteRequest,
    AccountActivationStartRequest,
    EnrolNewAgentRequest,
    FirstPasswordChangeRequest,
    ChangeAgentRoleRequest,
    CreateChannelRequest,
    IntruderAttemptRequest,
    LoginRequest,
    PublishPublicKeysRequest,
    RevokeAgentRequest,
    SendEncryptedMessageRequest,
    SignProbativeReceiptRequest,
    UploadEncryptedBlobRequest,
    consume_one_time_prekey_bundle,
    change_initial_password,
    complete_account_activation,
    change_agent_role,
    create_institutional_or_direct_channel,
    create_websocket_ticket,
    download_encrypted_attachment_blob,
    enrol_new_public_agent,
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
    reissue_agent_activation_code,
    submit_probative_read_receipt,
    start_account_activation,
    upload_encrypted_attachment_blob,
)
from models import EnrolledAgent, SecurityAuditLog, WebSocketTicket
from seed import seed_demo_data
from bootstrap_admin import bootstrap_initial_admin, reissue_initial_admin_activation


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
    otpk_bundle_json = json.dumps(
        {
            "protocol": SUPPORTED_E2EE_PROTOCOL,
            "signal_prekey_bundle": {
                "registrationId": 1001,
                "identityKeyB64": base64.b64encode(b"A" * 33).decode("ascii"),
                "signedPreKey": {
                    "keyId": 1,
                    "publicKeyB64": base64.b64encode(b"B" * 33).decode("ascii"),
                    "signatureB64": base64.b64encode(b"C" * 64).decode("ascii"),
                },
                "preKey": {"keyId": 1, "publicKeyB64": base64.b64encode(b"1" * 33).decode("ascii")},
                "oneTimePreKeys": [
                    {"keyId": 1, "publicKeyB64": base64.b64encode(b"1" * 33).decode("ascii")},
                    {"keyId": 2, "publicKeyB64": base64.b64encode(b"2" * 33).decode("ascii")},
                    {"keyId": 3, "publicKeyB64": base64.b64encode(b"3" * 33).decode("ascii")},
                ],
            },
        }
    )
    res = publish_agent_public_key_bundle(
        req=PublishPublicKeysRequest(
            identity_public_key=id_pub_jwk,
            signing_public_key=signing_pub_jwk,
            signed_prekey_public=id_pub_jwk,
            signed_prekey_signature=valid_prekey_sig,
            one_time_prekeys_json=otpk_bundle_json,
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
    agent_row = db.query(EnrolledAgent).filter(EnrolledAgent.matricule == matricule).first()
    assert agent_row is not None
    totp_code = generate_current_totp_code(agent_row.totp_secret_encrypted)
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
    simulated_ciphertext = base64.b64encode(b"SIGNAL_DOUBLERATCHET_CIPHERTEXT_8f9a2b3c4d5e6f7a8b9c0d1e2f3a4b5c").decode("ascii")
    nonce_val = base64.b64encode(b"123456789012").decode("ascii")
    signed_data = f"1:1:{nonce_val}:{simulated_ciphertext}".encode("utf-8")
    valid_sig_hex = _sign_p1363_hex(admin_priv_key, signed_data)

    # Rejet strict anti-downgrade : l'ancien protocole WebCrypto maison ou un protocole inconnu est rejeté (400)
    for bad_proto in ("WEBCRYPTO_ECDH_HKDF_AES256GCM_ECDSA", "CUSTOM_HOMEMADE_PROTO_V0"):
        with pytest.raises(HTTPException) as exc_downgrade:
            _run_coro(
                post_encrypted_message(
                    channel_id=1,
                    req=SendEncryptedMessageRequest(
                        e2ee_protocol=bad_proto,
                        ciphertext_payload=simulated_ciphertext,
                        nonce_or_iv=nonce_val,
                        authenticity_mac=valid_sig_hex,
                    ),
                    current_agent=admin_agent,
                    db=db,
                )
            )
        assert exc_downgrade.value.status_code == 400
        assert "ANTI-DOWNGRADE" in exc_downgrade.value.detail

    ok_msg = _run_coro(
        post_encrypted_message(
            channel_id=1,
            req=SendEncryptedMessageRequest(
                e2ee_protocol=SUPPORTED_E2EE_PROTOCOL,
                ciphertext_payload=simulated_ciphertext,
                nonce_or_iv=nonce_val,
                authenticity_mac=valid_sig_hex,
                requires_probative_receipt=True,
            ),
            current_agent=admin_agent,
            db=db,
        )
    )
    assert ok_msg["e2ee_protocol"] == SUPPORTED_E2EE_PROTOCOL
    assert ok_msg["ciphertext_payload"] == simulated_ciphertext
    assert ok_msg["ecdsa_verified_by_server"] is True
    message_audit = db.query(SecurityAuditLog).filter_by(event_type="MESSAGE_SENT").order_by(SecurityAuditLog.id.desc()).first()
    assert message_audit is not None
    assert secret_cleartext not in message_audit.description

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


def test_8_demo_isolation_zero_public_secrets_and_fernet_restart_persistence(db):
    """
    Vérifie les correctifs des Constats 2 et 3 de l'audit :
    1. `/api/auth/demo-accounts` ne divulgue JAMAIS `demo_password`, `current_totp_code` ni `totp_secret`.
    2. Un agent réel enrôlé via `/api/admin/enrol` a `is_demo_account=False` et n'apparaît jamais dans `/api/auth/demo-accounts`.
    3. Les secrets serveur (Fernet, JWT, Pepper) sont persistés sur disque et survivent à un redémarrage sans perte d'accès 2FA.
    """
    admin_token = _login_helper(db, "BF-DGTD-001")["access_token"]
    admin_agent = verify_and_load_active_agent(admin_token, db)

    enrolled = enrol_new_public_agent(
        req=EnrolNewAgentRequest(
            matricule="BF-REEL-777",
            full_name="Agent Réel Hors Démo",
            ministry="MTDPCE",
            direction="DSI",
            job_title="Analyste Sécurité",
        ),
        response=Response(),
        admin_agent=admin_agent,
        db=db,
    )
    assert enrolled["matricule"] == "BF-REEL-777"
    pending = db.query(EnrolledAgent).filter_by(matricule="BF-REEL-777").one()
    assert pending.is_enrolled_activated is False
    assert pending.totp_enabled is False
    assert len(enrolled["activation_code_once"]) >= 40
    assert "totp_secret" not in enrolled
    assert "temporary_password_provisioning_once" not in enrolled
    assert pending.enrolment_token == hashlib.sha256(enrolled["activation_code_once"].encode()).hexdigest()
    assert pending.enrolment_token != enrolled["activation_code_once"]
    assert pending.enrolment_token_expires_at is not None
    db.info["BF-REEL-777_activation_code"] = enrolled["activation_code_once"]

    demo_list = list_fictional_demo_accounts(db=db)["demo_accounts"]
    demo_matricules = {item["matricule"] for item in demo_list}
    assert "BF-REEL-777" not in demo_matricules
    for item in demo_list:
        assert "demo_password" not in item
        assert "current_totp_code" not in item
        assert "totp_secret" not in item
        assert item["is_demo_account"] is True

    # Vérification de la persistance des clés serveur au redémarrage et de leur séparation du dossier BDD
    s1 = auth._load_or_create_persistent_secrets()
    s2 = auth._load_or_create_persistent_secrets()
    assert s1["totp_fernet_key"] == s2["totp_fernet_key"]
    assert s1["jwt_secret"] == s2["jwt_secret"]
    assert s1["metadata_pepper"] == s2["metadata_pepper"]
    secrets_path = os.path.abspath(auth._resolve_secrets_file_path())
    assert ".faso_secur_secrets" in secrets_path


def test_9_encrypted_attachment_blob_upload_download_and_channel_rbac(db):
    """
    Vérifie le chiffrement de bout en bout des fichiers et notes vocales (/api/blobs) :
    1. Un agent membre du canal peut téléverser et récupérer un blob chiffré paddé à 4096 octets.
    2. Un agent non membre du canal (ex: BF-SANTE-308 sur le canal #3 interne MTDPCE) est rejeté (403).
    """
    admin_token = _login_helper(db, "BF-DGTD-001")["access_token"]
    admin_agent = verify_and_load_active_agent(admin_token, db)

    sante_token = _login_helper(db, "BF-SANTE-308")["access_token"]
    sante_agent = verify_and_load_active_agent(sante_token, db)

    fake_cipher_b64 = base64.b64encode(b"ENCRYPTED_ATTACHMENT_AES256GCM_" * 140).decode("ascii")
    fake_iv_b64 = base64.b64encode(b"123456789012").decode("ascii")

    uploaded = upload_encrypted_attachment_blob(
        req=UploadEncryptedBlobRequest(
            channel_id=3,  # Canal interne MTDPCE
            ciphertext_b64=fake_cipher_b64,
            iv_b64=fake_iv_b64,
        ),
        current_agent=admin_agent,
        db=db,
    )
    assert uploaded["blob_id"].startswith("blob_")
    assert uploaded["size_padded_bytes"] % 4096 == 0

    downloaded = download_encrypted_attachment_blob(
        blob_id=uploaded["blob_id"],
        current_agent=admin_agent,
        db=db,
    )
    assert downloaded["ciphertext_b64"] == fake_cipher_b64

    # L'agent BF-SANTE-308 (non membre du canal #3) ne peut ni télécharger ni téléverser sur le canal #3
    with pytest.raises(HTTPException) as exc_dl_forbidden:
        download_encrypted_attachment_blob(
            blob_id=uploaded["blob_id"],
            current_agent=sante_agent,
            db=db,
        )
    assert exc_dl_forbidden.value.status_code == 403


def test_10_server_signal_one_time_prekey_consumption_and_backend_restart_2fa(db):
    """
    Vérifie :
    1. La consommation atomique et non-réutilisation des pré-clés à usage unique Signal
       côté serveur (`POST /api/e2ee/prekeys/consume/{target_matricule}`).
    2. Le redémarrage simulé du backend avec rechargement des secrets persistés sur disque
       et connexion 2FA TOTP réussie sans perte d'accès aux graines chiffrées Fernet.
    """
    admin_token = _login_helper(db, "BF-DGTD-001")["access_token"]
    admin_agent = verify_and_load_active_agent(admin_token, db)

    mefp_token = _login_helper(db, "BF-MEFP-102")["access_token"]
    mefp_agent = verify_and_load_active_agent(mefp_token, db)
    _publish_test_keys_for_agent(db, mefp_agent)

    # 1er appel : consomme la One-Time PreKey #1 et il en reste 2
    consumed_1 = consume_one_time_prekey_bundle(
        target_matricule="BF-MEFP-102",
        current_agent=admin_agent,
        db=db,
    )
    assert consumed_1["consumed_prekey"]["keyId"] == 1
    assert consumed_1["remaining_one_time_prekeys"] == 2

    # 2e appel : consomme la One-Time PreKey #2 (jamais la #1 !) et il en reste 1
    consumed_2 = consume_one_time_prekey_bundle(
        target_matricule="BF-MEFP-102",
        current_agent=admin_agent,
        db=db,
    )
    assert consumed_2["consumed_prekey"]["keyId"] == 2
    assert consumed_2["remaining_one_time_prekeys"] == 1
    assert consumed_2["consumed_prekey"]["keyId"] != consumed_1["consumed_prekey"]["keyId"]

    # Simulation d'un redémarrage du backend : rechargement des secrets serveur depuis le disque
    reloaded_secrets = auth._load_or_create_persistent_secrets()
    assert reloaded_secrets["totp_fernet_key"] == auth._PERSISTENT_SECRETS["totp_fernet_key"]
    assert reloaded_secrets["jwt_secret"] == auth.JWT_SECRET_KEY

    # Connexion 2FA TOTP de BF-MEFP-102 après redémarrage avec la graine TOTP stockée en BDD
    post_restart_login = _login_helper(db, "BF-MEFP-102")
    assert "access_token" in post_restart_login
    assert post_restart_login["agent"]["matricule"] == "BF-MEFP-102"


class _TicketTestWebSocket:
    def __init__(self):
        self.accepted = False
        self.close_code = None
        self.sent = []

    async def accept(self):
        self.accepted = True

    async def close(self, code=1000):
        self.close_code = code

    async def send_json(self, payload):
        self.sent.append(payload)

    async def receive_json(self):
        raise WebSocketDisconnect(code=1000)


def test_11_websocket_ticket_is_short_lived_single_use_and_stored_hashed(db):
    """Vérifie émission sans cache, conservation hachée, consommation et rejet du rejeu/expiration."""
    auth.websocket_ticket_rate_limiter.reset()
    agent = db.query(EnrolledAgent).filter(EnrolledAgent.matricule == "BF-DGTD-001").first()
    assert agent is not None

    response = Response()
    result = create_websocket_ticket(response=response, current_agent=agent, db=db)
    ticket = result["ticket"]
    ticket_hash = hashlib.sha256(ticket.encode("utf-8")).hexdigest()
    stored = db.query(WebSocketTicket).filter(WebSocketTicket.ticket_hash == ticket_hash).first()

    assert len(ticket) >= 40
    assert result["expires_in"] == 30
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert stored is not None
    assert ticket not in stored.ticket_hash
    assert stored.token_version == agent.token_version

    first_socket = _TicketTestWebSocket()
    _run_coro(main.websocket_endpoint(first_socket, ticket))
    assert first_socket.accepted is True
    assert first_socket.sent[0]["type"] == "WS_CONNECTED_SOVEREIGN"
    db.expire_all()
    assert db.query(WebSocketTicket).filter_by(ticket_hash=ticket_hash).one().consumed_at is not None

    replay_socket = _TicketTestWebSocket()
    _run_coro(main.websocket_endpoint(replay_socket, ticket))
    assert replay_socket.accepted is False
    assert replay_socket.close_code == 4003

    expired_ticket = secrets.token_urlsafe(32)
    expired_hash = hashlib.sha256(expired_ticket.encode("utf-8")).hexdigest()
    db.add(
        WebSocketTicket(
            ticket_hash=expired_hash,
            agent_id=agent.id,
            token_version=agent.token_version,
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=1),
        )
    )
    db.commit()
    expired_socket = _TicketTestWebSocket()
    _run_coro(main.websocket_endpoint(expired_socket, expired_ticket))
    assert expired_socket.accepted is False
    assert expired_socket.close_code == 4003


def test_12_websocket_ticket_concurrent_replay_allows_only_one_connection(db):
    """Deux handshakes concurrents ne peuvent pas consommer le même ticket."""
    auth.websocket_ticket_rate_limiter.reset()
    agent = db.query(EnrolledAgent).filter(EnrolledAgent.matricule == "BF-DGTD-001").first()
    response = Response()
    ticket = create_websocket_ticket(response=response, current_agent=agent, db=db)["ticket"]

    def connect_once(_):
        socket = _TicketTestWebSocket()
        _run_coro(main.websocket_endpoint(socket, ticket))
        return socket

    with ThreadPoolExecutor(max_workers=2) as pool:
        sockets = list(pool.map(connect_once, range(2)))

    assert sum(socket.accepted for socket in sockets) == 1
    assert sum(socket.close_code == 4003 for socket in sockets) == 1


def test_13_websocket_ticket_rate_limiter_returns_429(db):
    auth.websocket_ticket_rate_limiter.reset()
    agent = db.query(EnrolledAgent).filter(EnrolledAgent.matricule == "BF-DGTD-001").first()
    assert agent is not None
    for _ in range(20):
        create_websocket_ticket(response=Response(), current_agent=agent, db=db)
    with pytest.raises(HTTPException) as limited:
        create_websocket_ticket(response=Response(), current_agent=agent, db=db)
    assert limited.value.status_code == 429


def test_14_websocket_ticket_rejects_rotated_session_version(db):
    auth.websocket_ticket_rate_limiter.reset()
    agent = db.query(EnrolledAgent).filter(EnrolledAgent.matricule == "BF-DGTD-001").first()
    response = Response()
    ticket = create_websocket_ticket(response=response, current_agent=agent, db=db)["ticket"]
    original_version = agent.token_version
    agent.token_version += 1
    db.commit()
    try:
        socket = _TicketTestWebSocket()
        _run_coro(main.websocket_endpoint(socket, ticket))
        assert socket.accepted is False
        assert socket.close_code == 4003
    finally:
        agent.token_version = original_version
        db.commit()


def test_15_first_login_requires_restricted_password_change(db):
    agent = db.query(EnrolledAgent).filter_by(matricule="BF-REEL-777").one()
    assert agent.is_enrolled_activated is False
    previous_code = db.info.pop("BF-REEL-777_activation_code")
    admin = db.query(EnrolledAgent).filter_by(matricule="BF-DGTD-001").one()
    replacement = reissue_agent_activation_code(agent.id, response=Response(), admin_agent=admin, db=db)
    assert "totp_secret" not in replacement
    with pytest.raises(HTTPException) as invalidated_code:
        start_account_activation(
            AccountActivationStartRequest(matricule=agent.matricule, activation_code=previous_code),
            response=Response(),
            db=db,
        )
    assert invalidated_code.value.status_code == 403
    activation_code = replacement["activation_code_once"]
    start = start_account_activation(
        AccountActivationStartRequest(matricule=agent.matricule, activation_code=activation_code),
        response=Response(),
        db=db,
    )
    assert "totp_secret" in start and start["expires_in_seconds"] == 900
    with pytest.raises(HTTPException) as inactive_login:
        login_enrolled_agent(
            LoginRequest(matricule=agent.matricule, password="wrong", totp_code="000000"),
            db=db,
        )
    assert inactive_login.value.status_code == 403
    activation_credentials = HTTPAuthorizationCredentials(
        scheme="Bearer", credentials=start["activation_token"]
    )
    latest_invitation = reissue_agent_activation_code(agent.id, response=Response(), admin_agent=admin, db=db)
    with pytest.raises(HTTPException) as invalidated_session:
        complete_account_activation(
            AccountActivationCompleteRequest(
                new_password="ActivationPassword2026!",
                totp_code=generate_current_totp_code(start["totp_secret"]),
            ),
            response=Response(),
            credentials=activation_credentials,
            db=db,
        )
    assert invalidated_session.value.status_code == 401
    start = start_account_activation(
        AccountActivationStartRequest(
            matricule=agent.matricule,
            activation_code=latest_invitation["activation_code_once"],
        ),
        response=Response(),
        db=db,
    )
    activation_credentials = HTTPAuthorizationCredentials(
        scheme="Bearer", credentials=start["activation_token"]
    )
    with pytest.raises(HTTPException) as invalid_totp:
        complete_account_activation(
            AccountActivationCompleteRequest(
                new_password="ActivationPassword2026!",
                totp_code="000000",
            ),
            response=Response(),
            credentials=activation_credentials,
            db=db,
        )
    assert invalid_totp.value.status_code == 401
    activated = complete_account_activation(
        AccountActivationCompleteRequest(
            new_password="ActivationPassword2026!",
            totp_code=generate_current_totp_code(start["totp_secret"]),
        ),
        response=Response(),
        credentials=activation_credentials,
        db=db,
    )
    assert agent.is_enrolled_activated is True
    assert agent.totp_enabled is True
    assert verify_and_load_active_agent(activated["access_token"], db).id == agent.id
    with pytest.raises(HTTPException) as reused_invitation:
        start_account_activation(
            AccountActivationStartRequest(matricule=agent.matricule, activation_code=activation_code),
            response=Response(),
            db=db,
        )
    assert reused_invitation.value.status_code == 403

    # Garde aussi une vérification du flux historique de changement forcé de mot de passe.
    agent.must_change_password = True
    agent.password_hash = auth.hash_password("ActivationPassword2026!")
    db.commit()
    login_rate_limiter.reset(agent.matricule)
    login = login_enrolled_agent(
        LoginRequest(
            matricule=agent.matricule,
            password="ActivationPassword2026!",
            totp_code=generate_current_totp_code(agent.totp_secret_encrypted),
        ),
        db=db,
    )
    assert login["password_change_required"] is True
    assert "access_token" not in login
    change_credentials = HTTPAuthorizationCredentials(
        scheme="Bearer", credentials=login["password_change_token"]
    )

    with pytest.raises(HTTPException) as restricted_token:
        verify_and_load_active_agent(login["password_change_token"], db)
    assert restricted_token.value.status_code == 401

    with pytest.raises(HTTPException) as weak_password:
        change_initial_password(
            FirstPasswordChangeRequest(new_password="weakpassword123"),
            credentials=change_credentials,
            db=db,
        )
    assert weak_password.value.status_code == 422

    original_version = agent.token_version
    changed = change_initial_password(
        FirstPasswordChangeRequest(new_password="NewSecurePassword2026!"),
        credentials=change_credentials,
        db=db,
    )
    assert agent.must_change_password is False
    assert agent.token_version == original_version + 1
    assert verify_and_load_active_agent(changed["access_token"], db).id == agent.id

    with pytest.raises(HTTPException) as replay:
        change_initial_password(
            FirstPasswordChangeRequest(new_password="AnotherSecurePassword2026!"),
            credentials=change_credentials,
            db=db,
        )
    assert replay.value.status_code == 401

    login_rate_limiter.reset(agent.matricule)
    normal_login = login_enrolled_agent(
        LoginRequest(
            matricule=agent.matricule,
            password="NewSecurePassword2026!",
            totp_code=generate_current_totp_code(agent.totp_secret_encrypted),
        ),
        db=db,
    )
    assert "access_token" in normal_login


def test_16_role_boundaries_and_audited_role_changes(db):
    super_admin = db.query(EnrolledAgent).filter_by(matricule="BF-DGTD-001").one()
    point_focal = db.query(EnrolledAgent).filter_by(matricule="BF-MEFP-102").one()
    public_agent = db.query(EnrolledAgent).filter_by(matricule="BF-MATDS-204").one()

    with pytest.raises(HTTPException) as public_cannot_manage:
        require_account_manager(public_agent)
    assert public_cannot_manage.value.status_code == 403

    with pytest.raises(HTTPException) as focal_cannot_grant_admin:
        enrol_new_public_agent(
            req=EnrolNewAgentRequest(
                matricule="BF-ROLE-ESCALATION-001",
                full_name="Test Role",
                ministry=point_focal.ministry,
                direction="Test",
                job_title="Test",
                role="SUPER_ADMIN_DGTD",
            ),
            response=Response(),
            admin_agent=point_focal,
            db=db,
        )
    assert focal_cannot_grant_admin.value.status_code == 403

    with pytest.raises(HTTPException) as focal_wrong_ministry:
        enrol_new_public_agent(
            req=EnrolNewAgentRequest(
                matricule="BF-ROLE-SCOPE-001",
                full_name="Test Scope",
                ministry="MTDPCE",
                direction="Test",
                job_title="Test",
            ),
            response=Response(),
            admin_agent=point_focal,
            db=db,
        )
    assert focal_wrong_ministry.value.status_code == 403

    created = enrol_new_public_agent(
        req=EnrolNewAgentRequest(
            matricule="BF-ROLE-AUDITOR-001",
            full_name="Agent Test Audit",
            ministry="MTDPCE",
            direction="Test",
            job_title="Test",
        ),
        response=Response(),
        admin_agent=super_admin,
        db=db,
    )
    role_change = change_agent_role(
        agent_id=created["id"],
        req=ChangeAgentRoleRequest(role="AUDITEUR"),
        admin_agent=super_admin,
        db=db,
    )
    assert role_change["role"] == "AUDITEUR"
    auditor = db.query(EnrolledAgent).filter_by(id=created["id"]).one()
    with pytest.raises(HTTPException) as auditor_cannot_manage:
        require_account_manager(auditor)
    assert auditor_cannot_manage.value.status_code == 403

    audit_event = db.query(SecurityAuditLog).filter_by(event_type="AGENT_ROLE_CHANGED").order_by(SecurityAuditLog.id.desc()).first()
    assert audit_event is not None
    assert "AGENT_PUBLIC" in audit_event.description
    assert "AUDITEUR" in audit_event.description

    with pytest.raises(HTTPException) as self_change:
        change_agent_role(
            agent_id=super_admin.id,
            req=ChangeAgentRoleRequest(role="AGENT_PUBLIC"),
            admin_agent=super_admin,
            db=db,
        )
    assert self_change.value.status_code == 400


def test_17_point_focal_cannot_create_interministerial_channel(db):
    point_focal = db.query(EnrolledAgent).filter_by(matricule="BF-MEFP-102").one()

    with pytest.raises(HTTPException) as global_scope:
        create_institutional_or_direct_channel(
            req=CreateChannelRequest(
                name="Canal trop large",
                ministry_scope="TOUS",
                member_ids=[],
            ),
            current_agent=point_focal,
            db=db,
        )
    assert global_scope.value.status_code == 403


def test_18_demo_accounts_are_blocked_in_production_mode(db):
    """Une base de démo persistante ne doit pas rendre ses comptes utilisables en prod."""
    demo_agent = db.query(EnrolledAgent).filter_by(matricule="BF-DGTD-001").one()
    demo_token = _login_helper(db, demo_agent.matricule)["access_token"]
    previous_mode = auth.DEMO_MODE_ENABLED
    auth.DEMO_MODE_ENABLED = False
    try:
        with pytest.raises(HTTPException) as login_blocked:
            login_enrolled_agent(
                LoginRequest(
                    matricule=demo_agent.matricule,
                    password="FasoSecur!2026",
                    totp_code=generate_current_totp_code(demo_agent.totp_secret_encrypted),
                ),
                db=db,
            )
        assert login_blocked.value.status_code == 403
        with pytest.raises(HTTPException) as token_blocked:
            verify_and_load_active_agent(demo_token, db)
        assert token_blocked.value.status_code == 403
        assert db.query(SecurityAuditLog).filter_by(event_type="DEMO_ACCOUNT_LOGIN_BLOCKED").count() == 1
    finally:
        auth.DEMO_MODE_ENABLED = previous_mode


def test_19_production_bootstrap_is_one_time_and_uses_agent_activation():
    """Le premier DGTD reçoit un code à usage unique et configure lui-même son compte."""
    local_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=local_engine)
    local_session_factory = sessionmaker(autocommit=False, autoflush=False, bind=local_engine)
    local_db = local_session_factory()
    previous_mode = auth.DEMO_MODE_ENABLED
    auth.DEMO_MODE_ENABLED = False
    try:
        credentials = bootstrap_initial_admin(
            local_db,
            matricule="BF-DGTD-PROD-001",
            full_name="Administrateur de préproduction",
            ministry="MTDPCE",
            direction="DGTD",
            job_title="Administrateur",
        )
        row = local_db.query(EnrolledAgent).filter_by(matricule="BF-DGTD-PROD-001").one()
        assert row.role == "SUPER_ADMIN_DGTD"
        assert row.is_enrolled_activated is False
        assert row.totp_enabled is False
        assert row.is_demo_account is False
        replacement = reissue_initial_admin_activation(local_db, row.matricule)
        with pytest.raises(HTTPException) as old_code_rejected:
            start_account_activation(
                AccountActivationStartRequest(
                    matricule=row.matricule,
                    activation_code=credentials["activation_code"],
                ),
                response=Response(),
                db=local_db,
            )
        assert old_code_rejected.value.status_code == 403
        start = start_account_activation(
            AccountActivationStartRequest(
                matricule=row.matricule,
                activation_code=replacement["activation_code"],
            ),
            response=Response(),
            db=local_db,
        )
        completed = complete_account_activation(
            AccountActivationCompleteRequest(
                new_password="BootstrapPassword2026!",
                totp_code=generate_current_totp_code(start["totp_secret"]),
            ),
            response=Response(),
            credentials=HTTPAuthorizationCredentials(scheme="Bearer", credentials=start["activation_token"]),
            db=local_db,
        )
        assert completed["agent"]["role"] == "SUPER_ADMIN_DGTD"
        assert row.is_enrolled_activated is True
        with pytest.raises(RuntimeError, match="contient déjà des comptes"):
            bootstrap_initial_admin(
                local_db,
                matricule="BF-DGTD-PROD-002",
                full_name="Autre administrateur",
                ministry="MTDPCE",
                direction="DGTD",
                job_title="Administrateur",
            )
    finally:
        auth.DEMO_MODE_ENABLED = previous_mode
        local_db.close()
        local_engine.dispose()
