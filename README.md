# 🇧🇫 FASO-SÉCUR — La Messagerie Souveraine de l'Administration
**Sprint Technique Pré-Hackathon 226 (Édition 2026) — MTDPCE / DGTD • Burkina Faso**  
*« Solutions open source endogènes » (Document synthétique ≤ 2 pages)*

---

## 1. Concept & Niveau d'Engagement Open Source

**FASO-SÉCUR** est une messagerie instantanée souveraine, chiffrée de bout en bout (E2EE) et déployable en une seule commande sur l'infrastructure de l'État burkinabè (Cloud Gouvernemental / Datacenter DGTD). Elle permet aux agents publics d'échanger messages, instructions officielles, notes vocales en langues nationales et fichiers classifiés sans dépendre d'aucun service ni serveur tiers.

- **Licence de la distribution** : **GPL-3.0-only** ([`LICENSE`](./LICENSE)), cohérente avec le paquet frontend qui embarque `@privacyresearch/libsignal-protocol-typescript`. Le code original FASO-SÉCUR est également proposé sous **MIT** ([`LICENSE-MIT`](./LICENSE-MIT)).
- **Niveau d'engagement Open Source déclaré** : **Créer & Étendre** — Le projet intègre le **Protocole Signal** (`@privacyresearch/libsignal-protocol-typescript`, GPL-3.0-only) et les primitives standardisées **W3C WebCrypto** / **PyCA `cryptography`**.
- **Zéro dépendance externe** : Aucune API tierce (ni Firebase, ni CDN externe, ni service cloud privé) n'est requise.

---

## 2. Architecture & Protocole de Chiffrement de Bout en Bout (Signal / libsignal)

```
[Client React + Protocole Signal (@privacyresearch/libsignal-protocol-typescript) + W3C WebCrypto]
       │  (Sessions Signal Pair-à-Pair : X3DH SessionBuilder + Double Ratchet SessionCipher + ECDSA P-256)
       ▼
[Serveur Relais Zero-Knowledge (Python FastAPI + WebSockets + TLS 1.3 / WSS via Caddy)]
       │  (Authentification 2FA TOTP RFC 6238 chiffré Fernet + RBAC + Révocation & Anti-Downgrade)
       ▼
[Volumes Souverains Séparés : Base SQLite/PostgreSQL (/app/data) ≠ Coffre Secrets (/app/secrets)]
```

1. **Protocole Signal (`libsignal` X3DH + Double Ratchet pair-à-pair pour messages directs et de groupe)** :
   - **Échange de clés X3DH, Réservation Atomique & Réapprovisionnement (`@privacyresearch/libsignal-protocol-typescript`)** : Chaque agent génère localement via `KeyHelper` son `registrationId`, sa paire d'identité `Curve25519`, sa `SignedPreKey` signée `Ed25519` et un lot de **20 pré-clés à usage unique (`One-Time PreKeys`)**, ainsi qu'une clé d'annuaire `ECDSA P-256`. L'annuaire (`/api/directory`) et `/api/channels` n'exposent jamais la liste des `One-Time PreKeys` : avant d'ouvrir une nouvelle session Signal, l'émetteur appelle `POST /api/e2ee/prekeys/consume/{matricule}` qui vérifie que l'émetteur et le destinataire sont actifs et partagent un canal, applique un limiteur de débit, réserve atomiquement une pré-clé unique et journalise l'opération. Lorsque le stock baisse, le client le réapprovisionne de manière authentifiée et signée (`POST /api/e2ee/prekeys/replenish`) avec des `keyId` strictement monotones sans jamais réutiliser une pré-clé consommée.
   - **Chiffrement des messages (1-à-1 et groupes) sans repli maison** : `@privacyresearch/libsignal-protocol-typescript` ne fournissant pas de primitive *Sender Key* de groupe, chaque message de salon (bourré par bloc de **256 octets**) est chiffré séparément pour chaque membre actif autorisé via sa session **Signal pair-à-pair** (`SessionBuilder.processPreKey` + `SessionCipher.encrypt` produisant un `PreKeyWhisperMessage` type 3 à l'amorçage puis un `WhisperMessage` type 1 lors du Double Ratchet). Tout repli vers l'ancien schéma HKDF WebCrypto est supprimé ; le serveur et le client rejettent toute enveloppe ne portant pas l'identifiant `SIGNAL_X3DH_DOUBLERATCHET_AES256GCM_ECDSA`.
   - **Pièces jointes et notes vocales E2EE** : Chaque fichier binaire est chiffré côté client avec une **clé symétrique aléatoire éphémère `AES-256-GCM` (256 bits)** et un IV de 96 bits après bourrage à **4 096 octets**. Le blob chiffré est téléversé une seule fois sur `/api/blobs` (sans la clé), et la clé symétrique `attachmentKeyB64` est distribuée exclusivement à l'intérieur des enveloppes Signal pair-à-pair des membres autorisés.
   - **Persistance sécurisée du trousseau et des sessions** : L'état complet du `SignalProtocolStore` (sessions Double Ratchet sérialisées, identités, pré-clés restantes et IDs consommés) est chiffré au repos dans `localStorage` par une `CryptoKey` maîtresse `AES-256-GCM` **non-extractible (`extractable: false`)** stockée dans `IndexedDB`, survivant aux rechargements du navigateur.
2. **Identité vérifiée, 2FA chiffré au repos, Séparation des secrets & Visibilité serveur** : Connexion réservée aux agents préalablement enrôlés (`bcrypt` + **2FA TOTP RFC 6238** chiffré au repos via **Fernet**). Les secrets serveur (`jwt_secret`, `metadata_pepper`, `totp_fernet_key`) sont stockés sur un volume dédié (`/app/secrets`) ou injectés via **Docker Secrets (`*_FILE`)**, séparés de la base (`/app/data`). Le JWT autorise les appels REST ; le WebSocket reçoit un ticket opaque à usage unique, valable 30 secondes, obtenu par un appel REST authentifié et stocké côté serveur uniquement sous forme hachée. Le serveur détient `METADATA_HMAC_PEPPER` : le champ `sender_pseudonym_hash` (`HMAC-SHA256`) et les slots déterministes (`SHA-256`) évitent les matricules en clair dans un export SQL au repos, mais ne rendent pas l'émetteur anonyme vis-à-vis du serveur actif.
3. **Révocation immédiate & Rotation d'époque (`crypto_epoch`)** : La révocation invalide immédiatement les JWT (`token_version`), retire l'agent des salons, incrémente `crypto_epoch` (excluant l'agent révoqué des enveloppes Signal suivantes) et envoie l'ordre WebSocket `REMOTE_WIPE_AND_REVOKE`.

---

## 3. Technologies Open Source Utilisées, Licences & Compatibilité

| Composant | Technologie Open Source | Licence OSI | Lien Officiel du Projet |
| :--- | :--- | :--- | :--- |
| **Protocole E2EE Signal** | `@privacyresearch/libsignal-protocol-typescript` | **GPL-3.0-only** | https://github.com/privacyresearchgroup/libsignal-protocol-typescript |
| **Protobuf Signal** | `@privacyresearch/libsignal-protocol-protobuf-ts` | **GPL-3.0-only** | https://github.com/privacyresearchgroup/libsignal-protocol-protobuf-ts |
| **Primitives WebCrypto** | W3C WebCrypto API (`SubtleCrypto` — BoringSSL/NSS) | W3C / BSD | https://www.w3.org/TR/WebCryptoAPI/ |
| **Backend API & Temps Réel** | FastAPI, Starlette & Uvicorn (Python) | MIT / BSD-3 | https://github.com/fastapi/fastapi |
| **Cryptographie Serveur** | PyCA `cryptography`, `bcrypt` & `PyJWT` | Apache-2.0 / MIT | https://github.com/pyca/cryptography |
| **ORM & Base de Données** | SQLAlchemy & SQLite / PostgreSQL | MIT License | https://github.com/sqlalchemy/sqlalchemy |
| **Interface Utilisateur Web** | React 18, Vite, Tailwind CSS & Lucide Icons | MIT / ISC | https://github.com/facebook/react |
| **Reverse-Proxy TLS 1.3** | Caddy Server 2 (Configuration réseau HTTPS/WSS) | Apache-2.0 | https://github.com/caddyserver/caddy |

> **Périmètre des licences** : La distribution du projet et le paquet frontend sont déclarés **GPL-3.0-only** ([`LICENSE`](./LICENSE), `frontend/package.json`). Le code original FASO-SÉCUR est en outre proposé sous **MIT** ([`LICENSE-MIT`](./LICENSE-MIT)). Les dépendances tierces gardent leurs propres licences, recensées dans [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md). Toute autre stratégie de redistribution doit être validée avant publication.

---

## 4. Installation Souveraine en Une Seule Commande & Approbation TLS

```bash
# 1. Déploiement sécurisé par défaut (FASO_SECUR_DEMO_MODE=false) :
docker compose up --build

# 2. Démarrage avec les comptes fictifs de démonstration activés pour le jury :
FASO_SECUR_DEMO_MODE=true docker compose up --build

# 3. Déploiement Réseau avec terminaison HTTPS / TLS 1.3 + WSS (Caddy sur :443 / :8443) :
FASO_SECUR_DEMO_MODE=true docker compose -f docker-compose.yml -f docker-compose.tls.yml up --build

# 4. Exécution des tests automatisés (14 tests Pytest Backend + 9 tests Node.js Signal E2EE) :
cd backend && python -m pytest -v
node frontend/tests/test_e2ee_engine.mjs
```
- **Approbation du certificat TLS sur les appareils clients** : En mode réseau (`docker-compose.tls.yml`), Caddy génère une Autorité de Certification (CA) interne (`tls internal`) nécessaire pour que les navigateurs activent `window.crypto.subtle` hors `localhost`. Pour approuver ce certificat sur les postes/téléphones du réseau local :
  1. Extraire le certificat racine : `docker compose -f docker-compose.yml -f docker-compose.tls.yml cp caddy-tls:/data/caddy/pki/authorities/local/root.crt ./faso-secur-root-ca.crt`
  2. **Windows** : `certutil -addstore -f "ROOT" .\faso-secur-root-ca.crt` (ou importer dans *Autorités de certification racines de confiance*).
  3. **Linux (Ubuntu/Debian)** : `sudo cp faso-secur-root-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`.
  4. **macOS / Android / iOS** : Importer `faso-secur-root-ca.crt` dans *Trousseau d'accès > Système* (macOS) ou *Paramètres > Sécurité > Chiffrement et identifiants > Installer un certificat CA* (Android).

## 5. Première activation sans service tiers

En production, démarrez d'abord l'application en mode non-démo et avec HTTPS sur le réseau gouvernemental. Sur une base neuve, un opérateur DGTD crée le compte initial depuis la console du backend :

```bash
docker compose exec faso-secur-backend python bootstrap_admin.py \
  --matricule BF-DGTD-001 \
  --nom "Administrateur DGTD" \
  --ministere "MTDPCE" \
  --direction "DGTD" \
  --fonction "Administrateur"
```

La commande affiche une seule fois un code d'activation à usage unique, valable 24 heures. Le code est stocké en base uniquement sous forme de condensat; aucun mot de passe ni secret TOTP n'est remis par l'opérateur. Celui-ci remet le code au titulaire en personne ou par un canal chiffré appartenant à l'administration. Ne pas le copier dans un courriel personnel, un service grand public, un ticket, une capture d'écran ou un terminal enregistré.

Le titulaire ouvre l'application sur son adresse HTTPS interne, choisit **« Activer mon compte »**, saisit son matricule et le code reçu, puis choisit son mot de passe. Le secret TOTP est alors transmis directement à son navigateur par la connexion HTTPS; le titulaire le configure dans l'application d'authentification approuvée par l'administration et valide le code à six chiffres. L'invitation est consommée une fois, la session d'activation expire après 15 minutes et l'accès normal n'est ouvert qu'après validation du TOTP.

Pour un agent enrôlé par un administrateur, l'écran d'administration affiche seulement le code d'invitation. Si le code est perdu ou si l'activation est interrompue, un responsable peut le réémettre depuis la fiche du compte; l'ancien code et les sessions d'activation précédentes deviennent alors invalides. Pour récupérer l'activation initiale DGTD avant qu'un administrateur soit actif, un opérateur autorisé peut exécuter `bootstrap_admin.py --matricule BF-DGTD-001 --reissue-initial-admin` depuis la même console privée.

---

## 6. Comptes Fictifs de Démonstration & Limites Connues Documentées

> **Isolation Démo vs Production** : Par défaut (`FASO_SECUR_DEMO_MODE=false`), aucun compte de démo n'est créé et `/api/auth/demo-accounts` retourne `403 Forbidden`. En mode démo (`FASO_SECUR_DEMO_MODE=true`), seuls les profils fictifs (`is_demo_account=True`) sont listés sans jamais exposer de mot de passe ni de code/graine TOTP sur le réseau.

| Matricule | Nom Fictif | Ministère / Direction | Rôle | Mot de passe | Secret 2FA Base32 (Initial) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `BF-DGTD-001` | Aminata OUÉDRAOGO | MTDPCE / DGTD | `SUPER_ADMIN_DGTD` | `FasoSecur!2026` | `JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXA` |
| `BF-MEFP-102` | Ibrahim SAWADOGO | MEFP / Trésor Public | `POINT_FOCAL` | `FasoSecur!2026` | `JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXB` |
| `BF-MATDS-204` | Moussa KABORÉ | MATDS / Territoire | `AGENT_PUBLIC` | `FasoSecur!2026` | `JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXC` |
| `BF-SANTE-308` | Fatimata DIALLO | MSHP / Santé | `AGENT_PUBLIC` | `FasoSecur!2026` | `JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXD` |
| `BF-MISSION-999` | Adama ZONGO | Mission Temporaire | `AGENT_PUBLIC` *(Cible Révocation)* | `FasoSecur!2026` | `JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXE` |

- **Limites connues documentées** : (1) Le chiffrement de groupe par sessions Signal pair-à-pair présente un coût linéaire $O(N)$ en nombre de membres actifs par message (adapté aux cellules ministérielles de taille modérée ; pour des milliers de membres, MLS RFC 9420 est recommandé) ; (2) si un appareil est **hors-ligne** lors d'une révocation, son accès serveur et aux nouvelles enveloppes Signal (`crypto_epoch + 1`) est coupé immédiatement, mais la purge locale (`REMOTE_WIPE`) ne s'exécute sur le terminal qu'à sa reconnexion ; (3) l'anti-capture Web est dissuasive (filigrane matricule).
