# 🔐 NOTE DE SÉCURITÉ — FASO-SÉCUR
**Sprint Technique Pré-Hackathon 226 (Édition 2026) — MTDPCE / DGTD • Burkina Faso**  
*Document officiel de conception cryptographique et d'analyse des menaces (Format ≤ 2 pages)*

## Authentification du WebSocket

Le JWT de session n'est pas placé dans l'URL du WebSocket. Le client demande un ticket via `POST /api/auth/ws-ticket` avec le JWT dans l'en-tête `Authorization`. Le serveur ne conserve que le SHA-256 du ticket ; celui-ci expire après 30 secondes et sa consommation est atomique et unique. Une révocation ou une rotation de version du jeton entre son émission et la connexion empêche l'ouverture du WebSocket. L'émission est limitée à 20 tickets par agent et par minute par processus. Pour un déploiement multi-workers, le limiteur devra être remplacé par un compteur partagé. La réponse est marquée `Cache-Control: no-store`.

---

## 1. Architecture Cryptographique E2EE (Protocole Signal Pair-à-Pair) & Zéro Cryptographie Maison

Conformément à l'interdiction absolue de développer un algorithme cryptographique « maison », **FASO-SÉCUR** s'appuie sur l'implémentation open source du **Protocole Signal** (`@privacyresearch/libsignal-protocol-typescript` + `@privacyresearch/libsignal-protocol-protobuf-ts`), exécutée sur l'API standardisée **W3C WebCrypto (`window.crypto.subtle`)** côté client, et sur **PyCA `cryptography`** + **`bcrypt`** côté serveur :

| Fonction de Sécurité | Protocole / Algorithme Standardisé | Bibliothèque Open Source | Rôle dans FASO-SÉCUR |
| :--- | :--- | :--- | :--- |
| **Accord de clés & Sessions E2EE** | **Protocole Signal (X3DH + Double Ratchet)** | `@privacyresearch/libsignal-protocol-typescript` | `KeyHelper`, `SessionBuilder.processPreKey`, `SessionCipher` (`PreKeyWhisperMessage` type 3 & `WhisperMessage` type 1) |
| **Messages directs & de groupe** | **Sessions Signal pair-à-pair** (bourrage **256 o.**) | `@privacyresearch/libsignal-protocol-typescript` | Chiffrement individuel par destinataire actif autorisé (`SIGNAL_PAIRWISE_ENVELOPE_V1`), sans repli HKDF maison |
| **Pièces jointes & Notes vocales** | **Clé aléatoire `AES-256-GCM`** distribuée via Signal | W3C WebCrypto + `libsignal` | Fichier bourré à **4 096 octets** chiffré avec une clé symétrique aléatoire fraîche (256 bits) transmise dans l'enveloppe Signal |
| **Authenticité & Reçus probants** | **ECDSA P-256 (`SHA-256`)** (FIPS 186-4) | W3C WebCrypto + PyCA `cryptography` | Signature obligatoire des enveloppes et des accusés de lecture vérifiée contre la clé publique d'annuaire |
| **Protection du trousseau local** | **Clé maîtresse non-extractible IndexedDB** | IndexedDB + WebCrypto `AES-256-GCM` | `CryptoKey` (`extractable: false`) chiffrant au repos l'état complet du `SignalProtocolStore` dans `localStorage` |
| **Authentification & 2FA au repos** | **Bcrypt** + **TOTP RFC 6238** chiffré **Fernet** | `bcrypt` + PyCA `cryptography.fernet` | Hachage salé des mots de passe et chiffrement au repos des graines 2FA TOTP via `FASO_SECUR_TOTP_FERNET_KEY` |

---

## 2. Chiffrement de Groupe par Sessions Signal Pair-à-Pair, Pièces Jointes & Anti-Downgrade

1. **Pourquoi des sessions Signal pair-à-pair pour les groupes** : La bibliothèque `@privacyresearch/libsignal-protocol-typescript` implémente les spécifications **X3DH** et **Double Ratchet** (`SessionBuilder` et `SessionCipher`) mais n'inclut pas le composant *Sender Keys* de groupe. Afin de garantir que **100 % des messages (directs et de groupe)** reposent réellement sur le protocole Signal autorisé sans aucun assemblage cryptographique maison, chaque message de salon (après bourrage à un multiple de **256 octets**) est chiffré séparément via la session `SessionCipher` de chaque membre actif autorisé du salon. Les emplacements destinataires et l'indice émetteur dans l'enveloppe JSON sont pseudonymisés par hachage `SHA-256` salé par salon et époque.
2. **Construction cryptographique pour les pièces jointes et notes vocales** :
   - Le client génère une clé symétrique aléatoire unique `attachmentKey` de **256 bits** (`CSPRNG`) et un vecteur d'initialisation `iv` de **96 bits**.
   - Le binaire est bourré à un multiple de **4 096 octets** puis chiffré en `AES-256-GCM` côté navigateur.
   - Le chiffré (`ciphertext_b64`, `iv_b64`) est téléversé une seule fois sur `POST /api/blobs` (**sans la clé**).
   - La clé `attachmentKeyB64` et le condensat `sha256Ciphertext` sont placés dans le `plaintextObject` du message, qui est chiffré de bout en bout via les sessions **Signal pair-à-pair** pour chaque membre autorisé. Le serveur ne détient jamais `attachmentKeyB64`.
3. **Consommation et non-réutilisation des pré-clés à usage unique (`One-Time PreKeys`)** : Chaque agent publie un lot initial de **20 `One-Time PreKeys`**. Lors de l'établissement d'une session X3DH, l'endpoint `POST /api/e2ee/prekeys/consume/{matricule}` retire atomiquement la pré-clé servie de la base serveur, et le destinataire la supprime définitivement de son `SignalProtocolStore` (`removePreKey` + suivi des `signalConsumedPreKeys` par `baseKey`) dès réception du `PreKeyWhisperMessage` (type 3). Toute tentative de réutiliser un `preKeyId` consommé pour initialiser une autre session est rejetée.
4. **Suppression de tout repli et protection Anti-Downgrade** : L'ancien chemin `WEBCRYPTO_ECDH_HKDF_AES256GCM_ECDSA` est supprimé. Le serveur (`POST /api/channels/{id}/messages` → `HTTP 400`) et le client (`decryptE2EEMessagePayload` → `isLegacyUnsupported: true`) rejettent toute enveloppe dont `e2ee_protocol` diffère de `SIGNAL_X3DH_DOUBLERATCHET_AES256GCM_ECDSA`.

---

## 3. Protection des Clés Côté Navigateur & Persistance des Sessions Signal

1. **Restauration complète après rechargement** : À chaque avancée du Double Ratchet (`storeSession`), mise à jour d'identité (`saveIdentity`) ou consommation de pré-clé (`removePreKey`), l'état sérialisé du `SignalProtocolStore` (`signalSessions`, `signalIdentities`, `signalPreKeys`, `signalConsumedPreKeys`) est ré-enveloppé en `AES-256-GCM` par la `CryptoKey` **non-extractible (`extractable: false`)** stockée dans `IndexedDB` (`FasoSecurHardwareKeystoreDB`) avant écriture dans `localStorage`. Après fermeture d'onglet ou rechargement du navigateur, les sessions Signal établies reprennent directement en `WhisperMessage` (type 1) sans réinitialiser X3DH.
2. **Évaluation honnête du modèle de menace navigateur (XSS / Même origine)** : L'utilisation d'une clé maîtresse non-extractible dans `IndexedDB` empêche l'exfiltration de la clé maîtresse brute. Toutefois, dans tout client Web, un script malveillant s'exécutant dans la **même origine (XSS)** pendant une session active pourrait invoquer l'API `IndexedDB` / `SubtleCrypto` pour déchiffrer le trousseau en mémoire. Ce risque est réduit par l'absence de tout script ou CDN tiers et l'isolation des composants React.

---

## 4. Révocation, Secrets Serveur & Métadonnées Visibles par le Serveur

1. **Révocation et exclusion cryptographique immédiate** : Lorsqu'un administrateur DGTD révoque un agent (`POST /api/admin/revoke/{id}`), le serveur incrémente `token_version` (bloquant immédiatement tout appel REST `403` et fermant le WebSocket `4003`), retire l'agent de `channel_members`, et incrémente `crypto_epoch` sur tous ses salons. Les messages suivants étant chiffrés par sessions Signal uniquement pour la liste des `active_members` non révoqués à l'époque `N+1`, l'agent révoqué ne reçoit plus aucune enveloppe Signal dans `recipients` et est mathématiquement incapable de déchiffrer les nouveaux échanges.
   - **Garantie réaliste de l'effacement à distance (`REMOTE_WIPE`)** : Si l'appareil est en ligne, la trame WebSocket `REMOTE_WIPE_AND_REVOKE` purge immédiatement `IndexedDB`, `localStorage`, `sessionStorage` et la RAM. Si l'appareil est **hors-ligne (mode avion)**, ses accès serveur et l'accès aux nouveaux messages sont coupés immédiatement, mais la purge du stockage local ne s'exécutera sur l'appareil qu'à sa première tentative de reconnexion HTTP/WebSocket.
2. **Persistance et séparation des secrets serveur** : `FASO_SECUR_JWT_SECRET`, `FASO_SECUR_METADATA_PEPPER` et `FASO_SECUR_TOTP_FERNET_KEY` sont chargés depuis les variables d'environnement ou fichiers Docker Secrets (`*_FILE`), ou persistés dans un répertoire dédié (`.faso_secur_secrets/.faso_secur_server_secrets.json` / volume `/app/secrets`) séparé du volume de base de données (`/app/data`), garantissant que les graines 2FA TOTP survivent aux redémarrages.

| Métadonnée Visible par le Serveur | Risque d'Inférence Associé | Mesure de Réduction Implémentée |
| :--- | :--- | :--- |
| **Auteur d'un message / upload** | Corrélation d'activité d'un agent | Pseudonymisation irréversible `HMAC-SHA256` (`sender_pseudonym_hash`, `uploader_pseudonym_hash`) |
| **Horodatage d'envoi** | Corrélation temporelle fine | Arrondi par tranche de **15 minutes** (`timestamp_bucket`, ex: `2026-10-28T16:45Z`) |
| **Taille des messages et fichiers** | Déduction du type ou de la longueur | Bourrage par blocs de **256 octets** (messages) et **4 096 octets** (fichiers `/api/blobs` : `size_padded_bytes`) |
| **Enveloppe de groupe Signal** | Nombre de destinataires actifs dans le salon | Emplacements destinataires hachés (`SHA-256(channel:epoch:matricule)`) sans matricule en clair |
| **Pièce jointe (`/api/blobs`)** | `blob_id`, `channel_id`, `sha256_ciphertext`, `size_padded_bytes` | Nom de fichier, type MIME et clé `attachmentKeyB64` scellés exclusivement dans l'enveloppe Signal |
