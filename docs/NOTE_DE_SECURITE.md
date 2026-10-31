# NOTE DE SÉCURITÉ — **FASO-SÉCUR**
**Sprint Technique Pré-Hackathon 226 (Édition 2026) — MTDPCE / DGTD • Burkina Faso**  
*Analyse des Menaces, Protections, Métadonnées et Limites Connues (Format 2 pages)*

---

### 1. Architecture Cryptographique E2EE (Protocole Signal Pair-à-Pair)

Conformément à l'interdiction stricte de toute cryptographie maison, **FASO-SÉCUR** repose intégralement sur l'implémentation officielle du **Protocole Signal** (`@privacyresearch/libsignal-protocol-typescript` + `@privacyresearch/libsignal-protocol-protobuf-ts`), couplée à l'API standard **W3C WebCrypto** (`window.crypto.subtle`) côté navigateur et **PyCA `cryptography`** côté serveur.

| Fonction de Sécurité | Protocole / Algorithme Standardisé | Bibliothèque Open Source | Rôle dans FASO-SÉCUR |
| :--- | :--- | :--- | :--- |
| **Accord de clés E2EE** | **Signal X3DH & Double Ratchet** | `@privacyresearch/libsignal-protocol-typescript` | `KeyHelper`, `SessionBuilder`, `SessionCipher` (`Curve25519` / `Ed25519`) |
| **Messages (Directs & Groupes)**| **Sessions Signal pair-à-pair** (bourrage 256 o.) | `@privacyresearch/libsignal-protocol-typescript` | Chiffrement individuel par membre actif autorisé, sans repli non éprouvé |
| **Pièces Jointes & Audio** | **AES-256-GCM** enveloppé dans Signal | W3C WebCrypto + `libsignal` | Clé symétrique aléatoire distribuée uniquement via les sessions Signal |
| **Accusés & Authenticité** | **ECDSA P-256 (SHA-256)** (FIPS 186-4) | W3C WebCrypto + PyCA `cryptography` | Signatures obligatoires vérifiées mathématiquement contre l'annuaire |
| **Protection Trousseau** | **Clé maîtresse non-extractible** | IndexedDB + WebCrypto `AES-256-GCM` | État sérialisé chiffré au repos dans IndexedDB (`extractable: false`) |
| **Authentification & 2FA** | **Bcrypt** + **TOTP RFC 6238 chiffré Fernet** | `bcrypt` + PyCA `cryptography.fernet` | Graines 2FA chiffrées au repos via `FASO_SECUR_TOTP_FERNET_KEY` |

---

### 2. Chiffrement de Groupe Signal, Pièces Jointes & Anti-Downgrade

1. **Pourquoi des sessions Signal pair-à-pair pour les groupes** : La bibliothèque Signal TypeScript n'implémentant pas les *Sender Keys* de groupe, FASO-SÉCUR chiffre chaque message de salon (bourré à un multiple de 256 octets) séparément pour chaque membre actif via sa session Signal (`SessionCipher.encrypt`). Cette construction garantit le **Forward Secrecy** et le **Break-in Recovery** au niveau de chaque message individuel sans aucun composant maison.
2. **Pièces jointes et notes vocales chiffrées** : Le fichier (bourré à 4 096 octets) est chiffré côté client avec une clé aléatoire fraîche `AES-256-GCM` (256 bits). Le chiffré est téléversé sans clé sur `POST /api/blobs`. La clé `attachmentKeyB64` est transmise exclusivement dans les enveloppes Signal des membres autorisés. Le serveur ne détient jamais la clé.
3. **Consommation stricte des pré-clés à usage unique (`One-Time PreKeys`)** : Lors de l'accord X3DH, `POST /api/e2ee/prekeys/consume/{matricule}` réserve et consomme atomiquement la pré-clé. Le client la supprime définitivement de son trousseau local. Toute réutilisation d'une pré-clé consommée est rejetée.
4. **Protection Anti-Downgrade** : Tout repli est supprimé. Le serveur (`HTTP 400`) et le client rejettent catégoriquement toute enveloppe dont le protocole diffère de `SIGNAL_X3DH_DOUBLERATCHET_AES256GCM_ECDSA`.

---

### 3. Modèle de Menace Navigateur & Sécurité des WebSockets

1. **Protection du trousseau local** : À chaque avancée du cliquet, l'état du trousseau est ré-enveloppé en `AES-256-GCM` par la clé maîtresse non-extractible stockée dans `IndexedDB`. Après fermeture ou rechargement, les sessions reprennent directement sans réinitialiser X3DH.
2. **Authentification du WebSocket sans token dans l'URL** : Le JWT n'apparaît jamais dans l'URL. Le client obtient un ticket temporaire (30 secondes, usage unique atomique, haché SHA-256) via `POST /api/auth/ws-ticket` transmis dans l'en-tête `Authorization`.
3. **Limites connues du navigateur** : La clé IndexedDB est non-extractible, mais une attaque par injection de script (XSS) au sein de la même origine pourrait appeler les APIs locales. Ce risque est maîtrisé par l'absence stricte de CDN tiers et une CSP restrictive.

---

### 4. Révocation Immédiate & Minimisation des Métadonnées

1. **Révocation en direct et exclusion cryptographique** : Lorsqu'un administrateur révoque un agent (`POST /api/admin/revoke/{id}`), le serveur invalide ses sessions (`token_version`), coupe son WebSocket (`4003`), et incrémente `crypto_epoch`. Les messages suivants étant chiffrés uniquement pour les membres actifs de l'époque `N+1`, l'agent révoqué ne peut plus rien déchiffrer.
   - **Garantie réaliste d'effacement (`REMOTE_WIPE`)** : En ligne, l'ordre WebSocket purge immédiatement le stockage local. Hors-ligne, l'accès aux nouveaux messages est coupé immédiatement et la purge locale s'exécute dès la première tentative de reconnexion.
2. **Minimisation des métadonnées visibles par le serveur et limites de la pseudonymisation** :
   - *Auteur d'un message* : Pseudonymisation par HMAC-SHA256 (`sender_pseudonym_hash`) avec secret poivré côté serveur.
   - *Slots destinataires de l'enveloppe Signal* : Indexés par `SHA-256(prefix:channel:epoch:matricule)`. **Limite reconnue dans notre modèle de menace** : ces slots masquent les matricules dans le transport JSON mais constituent une pseudonymisation déterministe (vulnérable à une attaque par dictionnaire si l'espace des matricules est restreint), et non une anonymisation forte. Le routage serveur s'opère sans lecture des contenus.
   - *Horodatage* : Arrondi par tranches temporelles de 5 minutes (`timestamp_bucket`).
   - *Tailles* : Bourrage systématique à 256 octets (messages) et 4 096 octets (fichiers). Le serveur ne voit ni noms de fichiers, ni types MIME, ni textes clairs.
