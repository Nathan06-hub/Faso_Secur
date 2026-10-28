# NOTE DE SÉCURITÉ — **FASO-SÉCUR**
**Sprint Technique Pré-Hackathon 226 (Édition 2026) — MTDPCE / DGTD • Burkina Faso**  
*Challenge : « La messagerie souveraine de l'administration » (Document limité à 2 pages)*

---

## 1. Modèle de Menaces Prises en Compte (Threat Model)

Dans le contexte des communications de l'administration publique burkinabè, FASO-SÉCUR prend en compte six menaces critiques :

| ID | Menace identifiée | Acteur menaçant | Impact potentiel |
| :--- | :--- | :--- | :--- |
| **M1** | **Compromission ou curiosité de l'hébergeur / BDD** : lecture de la base SQLite/PostgreSQL ou écoute du trafic sur le serveur. | Administrateur système malveillant, attaquant ayant obtenu un dump SQL. | Divulgation d'instructions ministérielles, de notes confidentielles ou de secrets 2FA. |
| **M2** | **Vol ou perte du terminal d'un agent sur le terrain** ou départ d'un agent de son service. | Tiers en possession physique du téléphone/PC ou ancien agent non habilité. | Accès non autorisé aux conversations en cours et aux nouveaux messages. |
| **M3** | **Intrusion d'un compte non enrôlé** ou usurpation d'identité par vol de mot de passe simple. | Attaquant externe tentant de s'inscrire ou de deviner un mot de passe. | Infiltration d'un groupe de travail interministériel. |
| **M4** | **Analyse de trafic et corrélation des métadonnées** (qui parle à qui, à quelle seconde exacte, taille et niveau de classification). | Observateur passif sur le serveur ou le réseau. | Cartographie de la chaîne de décision administrative. |
| **M5** | **Fuite visuelle ou transfert non autorisé** d'une note sensible (copier-coller, photo d'écran, partage). | Destinataire négligent ou indiscret. | Fuite d'un document classifié *Diffusion Restreinte* ou *Confidentiel*. |
| **M6** | **Répudiation ou falsification d'une instruction officielle** (usurpation d'émetteur ou déni de lecture). | Agent interne de mauvaise foi ou attaquant réseau. | Blocage administratif ou injection de fausse instruction. |

---

## 2. Protections Cryptographiques et Architecturales Mises en Place

### 2.1. Chiffrement de Bout en Bout, Accord ECDH P-256 & Vérification ECDSA Liée à l'Annuaire (Contre M1 & M6)
- **Zéro algorithme maison** : Utilisation exclusive des primitives natives auditées **W3C WebCrypto (`SubtleCrypto` — BoringSSL/NSS)** côté client et **`PyCA cryptography`** côté serveur.
- **Secret de groupe aléatoire CSPRNG & Encapsulage `ECDH P-256`** : Pour chaque salon et chaque époque (`crypto_epoch`), le premier membre connecté génère un secret aléatoire de 256 bits (`crypto.getRandomValues`) et l'encapsule individuellement pour la clé publique `ECDH P-256` de chaque membre actif (`deriveBits` + `HKDF-SHA256` + `AES-256-GCM`). Le serveur ne détenant aucune clé privée ECDH, un `SELECT *` en base ne permet jamais de dériver la clé de session.
- **Chiffrement `AES-256-GCM`, Bourrage 256 octets & Sealed Sender** : Tout contenu (texte, identité de l'émetteur, classification, drapeaux `noForward` / `antiScreenshot`) est bourré par blocs de 256 octets et chiffré dans `ciphertext_payload` avec un IV aléatoire de 96 bits (`nonce_or_iv`).
- **Vérification obligatoire des signatures `ECDSA P-256` contre l'annuaire** :
  - *Côté serveur* : `post_encrypted_message` et `submit_probative_read_receipt` vérifient obligatoirement la signature `ECDSA P-256` contre `current_agent.e2ee_signing_public_key` (clé certifiée dans l'annuaire lors de l'enrôlement), et jamais contre une clé fournie dans la requête.
  - *Côté client* : Au déchiffrement, le client vérifie la signature `ECDSA P-256` de l'enveloppe contre la clé publique d'annuaire du `senderMatricule` revendiqué dans le message déchiffré, empêchant tout membre d'usurper le matricule d'un pair.
- **Chiffrement CSPRNG du trousseau local** : Le trousseau local dans `localStorage` est chiffré en `AES-256-GCM` par une clé de session aléatoire de 256 bits (`CSPRNG`) stockée en mémoire de session (`sessionStorage`), non dérivable du seul matricule.

### 2.2. Enrôlement Strict, 2FA TOTP Chiffré au Repos (Fernet) & RBAC (Contre M1 & M3)
- **Zéro inscription publique & Anti-Brute-Force** : Seuls les matricules enrôlés par un administrateur (`SUPER_ADMIN_DGTD` ou `POINT_FOCAL`) peuvent se connecter. Tout intrus est rejeté (`403 Forbidden`) et journalisé ; 5 échecs consécutifs verrouillent temporairement le compte (`429 Too Many Requests`).
- **Double facteur obligatoire & Chiffrement Fernet au repos** :
  1. Mot de passe haché avec `bcrypt` (coût 12, salage unique).
  2. Code **TOTP à 6 chiffres (RFC 6238)** vérifié via `PyCA cryptography`. La graine `totp_secret_encrypted` est chiffrée au repos en base de données via **Fernet (`AES-128-CBC + HMAC-SHA256`)** : la lecture directe du fichier SQLite ne révèle aucun secret 2FA en clair.
- **Cloisonnement RBAC de l'inspecteur BDD** : L'endpoint `/api/jury/server-inspection` est restreint aux administrateurs/auditeurs (`require_admin_role`), filtre les messages aux seuls salons de l'appelant et calcule dynamiquement la conformité du schéma SQL.

### 2.3. Révocation Immédiate, Remote Wipe & Rotation des Clés de Groupe (Contre M2)
Lorsqu'un administrateur révoque un agent pendant une conversation :
1. **Invalidation instantanée des jetons** : `is_revoked` passe à `True`, `token_version` est incrémenté et ses clés publiques sont purgées de l'annuaire.
2. **Effacement à distance (`REMOTE_WIPE_AND_REVOKE`)** : Le serveur envoie une trame WebSocket prioritaire qui vide `localStorage`, `sessionStorage` et le cache mémoire du client révoqué, puis ferme la WebSocket (`Code 4003`).
3. **Retrait des salons & Rotation d'époque (`crypto_epoch`)** : L'agent est retiré de `channel_members` (avec sauvegarde de ses salons initiaux dans `revoked_channel_ids_json`) et `crypto_epoch` passe de `N` à `N+1`. Les membres restants génèrent et s'échangent via `ECDH P-256` un nouveau secret aléatoire de 256 bits pour l'époque `N+1`, excluant mathématiquement l'agent révoqué.

---

## 3. Métadonnées Visibles par le Serveur & Mesures de Minimisation (Contre M4)

| Métadonnée technique | Ce qu'un serveur classique voit | Mesure de minimisation implémentée dans FASO-SÉCUR |
| :--- | :--- | :--- |
| **Contenu, classification & drapeaux (`noForward`)** | Colonnes SQL en clair | **Totalement scellés dans `ciphertext_payload`** : `classification` et `message_kind` valent toujours `"SEALED_E2EE"` en base ; aucune colonne `no_forward` ou `anti_screenshot` en base. |
| **Identité de l'émetteur dans `encrypted_messages`** | `sender_id` ou clé publique en clair | **Zéro `sender_id` ni `sender_ephemeral_public_key`** en base : seul un pseudonyme `HMAC-SHA256` (`pseudo_<hmac>`) est stocké. |
| **Taille exacte des messages et fichiers** | Taille exacte à l'octet près | **Padding systématique** : messages texte bourrés par blocs de **256 octets** avant chiffrement ; pièces jointes et notes vocales bourrées par blocs de **4 096 octets**. |
| **Horodatage exact d'envoi** | Milliseconde exacte (`created_at`) | **Time-Bucketing (tranches de 5 minutes)** : aucune colonne `created_at` précise sur les messages ; seul `timestamp_bucket` (`HH:00`, `HH:05`…) est enregistré. |

---

## 4. Limites Connues & Perspectives d'Évolution (Transparence Architecturale)

1. **Protocole WebCrypto inspiré de Signal/Megolm vs Bibliothèque `@matrix-org/olm` (WASM)** : Le prototype assemble les primitives natives du navigateur (`ECDH P-256`, `HKDF-SHA256`, `AES-256-GCM`, `ECDSA P-256`) sans dépendance binaire externe. La clé de groupe tourne à chaque révocation (`crypto_epoch`), mais n'effectue pas de dérivation symétrique message par message (*per-message ratchet*) à l'intérieur d'une même époque. Le fichier [`e2eeEngine.js`](../frontend/src/crypto/e2eeEngine.js) expose une interface isolée permettant de brancher `@matrix-org/olm` / `vodozemac` (WASM) pour obtenir le Double Ratchet complet.
2. **Confiance dans l'annuaire de clés & Numéros de sécurité (Safety Numbers)** : Si le serveur lui-même était activement compromis au moment de l'échange initial des clés publiques, il pourrait tenter une substitution de clé (*MITM*). Pour contrer cette menace, FASO-SÉCUR affiche pour chaque agent un **Numéro de sécurité à 30 chiffres (`SHA-256`)** vérifiable hors-bande (par téléphone ou rencontre physique) et prépare l'intégration d'une transparence des clés (*Key Transparency*) signée par l'Autorité de Certification Nationale (PKI DGTD / ANSSI-BF).
3. **Protection anti-capture sur navigateur Web** : Le filigrane dynamique nominatif et le floutage anti-regard dissuadent et tracent les fuites visuelles sur navigateur, mais le blocage matériel des captures d'écran (`FLAG_SECURE`) requiert un conteneur natif mobile/desktop (Tauri / Flutter).
