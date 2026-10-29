# Journal des Modifications (CHANGELOG) — FASO-SÉCUR

Toutes les évolutions notables de **FASO-SÉCUR** pendant le Sprint Technique Pré-Hackathon 226 sont documentées dans ce fichier.

---

## [1.3.4] — 2026-10-29 (Harmonisation des mentions de licence)
- **Licence de distribution déclarée GPL-3.0-only** dans `LICENSE`, `frontend/package.json` et `frontend/package-lock.json`.
- **Conservation de la permission MIT** du code original dans `LICENSE-MIT`.
- **Synchronisation** du README, du guide de contribution, de la note de pré-projet et des notices tierces sur le périmètre de ces deux licences.
- **Mise à jour de l'interface** pour afficher la licence de distribution GPL-3.0-only.

---

## [1.3.3] — 2026-10-29 (Durcissement et tests du ticket WebSocket)
### Anti-abus et couverture du handshake
- **Limitation de débit des tickets WebSocket** : maximum 20 émissions par agent et par minute, avec compteur protégé contre les accès concurrents dans le processus.
- **Consommation compare-and-swap** : le serveur marque le ticket comme consommé dans une seule mise à jour conditionnelle avant de charger le compte, afin de rejeter les rejeux concurrents sur SQLite et PostgreSQL.
- **Nouveaux tests backend** : émission non cacheable, ticket haché, expiration, rejeu, concurrence, limitation de débit et révocation par changement de version de session.
- **Documentation** : comptage des tests backend actualisé à 14.

---

## [1.3.2] — 2026-10-29 (Corrections du ré-audit)
### Réduction de l'exposition des identifiants WebSocket et documentation
- **Retrait du JWT de l'URL WebSocket** : le client demande par REST authentifié un ticket opaque à usage unique, valable 30 secondes. Le serveur stocke son empreinte SHA-256 et consomme le ticket par mise à jour conditionnelle, avec contrôle du compte et de la version de session.
- **Réponse du ticket non cacheable** : ajout des en-têtes `Cache-Control: no-store` et `Pragma: no-cache`.
- **Synchronisation de `THIRD_PARTY_NOTICES.md`** avec les versions frontend verrouillées dans `package-lock.json` ; clarification du fait que les versions Python ne sont pas verrouillées par `requirements.txt`.
- **Documentation de l'authentification WebSocket** dans le README et la note de sécurité.

---

## [1.3.1] — 2026-10-29 (Remédiations Post-Audit Indépendant)
### Fiabilité Backend, Consommation X3DH Client & Durcissement Déploiement
- **Correction de la signature de `consume_one_time_prekey_bundle`** : Signature ajustée à `channel_id: Optional[int] = None` dans [`backend/main.py`](./backend/main.py), résolvant le conflit d'évaluation de l'objet `Query` et assurant **10/10 tests Pytest réussis (100 %)**.
- **Réservation atomique des pré-clés Signal dans le client Web (`App.jsx`)** : Intégration de `resolveActiveMembersPrekeys` interrogeant `POST /api/e2ee/prekeys/consume/{matricule}` pour chaque nouveau correspondant afin d'assurer l'injection effective d'une One-Time PreKey consommée avant l'amorçage X3DH.
- **Ajout de `hasEstablishedSignalSession` dans `e2eeEngine.js`** : Vérification locale des sessions actives évitant les requêtes réseau superflues une fois le Double Ratchet établi.
- **Durcissement de `frontend/Dockerfile` pour la production** : Compilation statique (`npm run build`) et exécution via `npm run preview` plutôt que le serveur de développement.
- **Découpage des modules Vite (`manualChunks`)** : Isolation de `vendor-react` et `vendor-crypto`, éliminant les avertissements de taille de bundle.
- **Synchronisation de `CONTRIBUTING.md`** : Alignement complet sur les 10 tests Pytest et les primitives Signal.

---

## [1.3.0] — 2026-10-28 (Intégration du Protocole Signal `libsignal` & Durcissement Production)
### Protocole E2EE, Séparation des Secrets & Déploiement HTTPS
- **Intégration réelle du Protocole Signal (`@privacyresearch/libsignal-protocol-typescript` v0.0.16, GPL-3.0)** :
  - Génération des clés Signal (`KeyHelper`: `registrationId`, `IdentityKeyPair` Curve25519, `SignedPreKey` signée Ed25519, `PreKeys` X3DH) dans [`e2eeEngine.js`](./frontend/src/crypto/e2eeEngine.js) et publication du `signal_prekey_bundle` dans l'annuaire souverain.
  - Encapsulage et désencapsulage des secrets de groupe 256 bits (`SenderKeyDistributionMessage`) via sessions **Signal X3DH + Double Ratchet** (`SessionBuilder.processPreKey` + `SessionCipher.encrypt` / `decryptPreKeyWhisperMessage`), signées en `ECDSA P-256`.
  - Implémentation et test des sessions directes 1-à-1 **Signal Double Ratchet** (`establishSignalDirectSession`, `encryptSignalDirectMessage`, `decryptSignalDirectMessage` : `PreKeyWhisperMessage` type 3 puis `WhisperMessage` type 1 bidirectionnel).
- **Séparation physique Base de Données / Secrets Serveur & Support Docker Secrets** :
  - Prise en charge de `FASO_SECUR_JWT_SECRET_FILE`, `FASO_SECUR_METADATA_PEPPER_FILE` et `FASO_SECUR_TOTP_FERNET_KEY_FILE` (et `/run/secrets/...`) dans [`backend/auth.py`](./backend/auth.py).
  - Séparation des volumes dans [`docker-compose.yml`](./docker-compose.yml) : `faso_secur_db_data:/app/data` (SQLite) distinct de `faso_secur_secrets_data:/app/secrets` (coffre de secrets serveur).
- **Déploiement Réseau HTTPS / TLS 1.3 + WSS** :
  - Ajout de [`docker-compose.tls.yml`](./docker-compose.tls.yml) et [`deploy/Caddyfile`](./deploy/Caddyfile) pour la terminaison TLS 1.3 et WebSockets sécurisés (`wss://`) avec en-têtes HSTS/CSP.
- **Extension des tests automatisés** : 9 tests Pytest backend ([`backend/tests/test_security.py`](./backend/tests/test_security.py)) et 6 tests unitaires client `libsignal` + WebCrypto ([`frontend/tests/test_e2ee_engine.mjs`](./frontend/tests/test_e2ee_engine.mjs)).

---

## [1.2.0] — 2026-10-28 (Plan de Correction Immédiat — Ré-Audit Indépendant)
### Sécurité, Cryptographie & Résilience
- **Persistance des clés serveur aux redémarrages (`FASO_SECUR_TOTP_FERNET_KEY`)** : Alignement de la variable `FASO_SECUR_TOTP_FERNET_KEY` entre `auth.py`, `docker-compose.yml` et `.env.example`, et persistance automatique en `0600` afin qu'aucun redémarrage serveur ne rende les graines TOTP indéchiffrables.
- **Mode démo désactivé par défaut & Isolation stricte (`is_demo_account`)** : `FASO_SECUR_DEMO_MODE=false` par défaut partout ; aucun compte administrateur n'est créé au démarrage sur une base vide hors mode démo ; suppression de tout `demo_password` et `current_totp_code` de la réponse publique `/api/auth/demo-accounts`.
- **Trousseau navigateur `IndexedDB` (`CryptoKey` `extractable: false`) & Persistance multi-onglets** : Survie des clés et des secrets d'époque chiffrés à la fermeture d'onglet ; signatures `ECDSA P-256` obligatoires sur les enveloppes de clés de groupe (`senderSignatureHex`) et résolution automatique des conflits `409` à la rotation d'époque.
- **Anti-usurpation d'émetteur (*Sender Spoofing*) & Bourrage binaire 4096 octets** : Validation stricte de `dec.signatureVerified` dans `App.jsx` (sans se fier au seul booléen serveur), dérivation de clé unique par message (`HKDF-SHA256` ratchet par nonce) et bourrage physique réel à 4096 octets des pièces jointes et notes vocales dans `encryptBinaryAttachmentE2EE`.

---

## [1.1.0] — 2026-10-28 (Durcissement Post-Audit de Sécurité)
### Sécurité & Cryptographie
- **Accord de clé Diffie-Hellman `ECDH P-256`** et vérification mathématique des signatures `ECDSA P-256` (Client + Serveur).
- **Architecture Sealed Sender intégrale** : Suppression de `sender_id` et de `created_at` milliseconde dans `encrypted_messages` ; scellement de `classification` et `message_kind` sous `"SEALED_E2EE"` en base de données.
- **Chiffrement au repos du trousseau local (`AES-256-GCM Key Wrapping`)** dans `localStorage`.
- **Protection Anti-Brute-Force (`HTTP 429`)** sur `/api/auth/login` après 5 tentatives échouées.

---

## [1.0.0] — 2026-10-28 (Version Initiale du Sprint)
- Serveur souverain Zero-Knowledge FastAPI + WebSockets temps réel.
- Authentification forte 2FA TOTP (RFC 6238) et gestion des rôles RBAC.
- Révocation immédiate en cours de conversation (`REMOTE_WIPE_AND_REVOKE` + rotation `crypto_epoch`).
- Client React multilingue (**Français, Mooré, Dioula, Fulfulde**) avec notes vocales E2EE, niveaux de classification et accusés de lecture à valeur probante.
