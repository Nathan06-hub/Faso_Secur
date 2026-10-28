# NOTE DE SÉCURITÉ — **FASO-SÉCUR**
**Sprint Technique Pré-Hackathon 226 (Édition 2026) — MTDPCE / DGTD • Burkina Faso**  
*Challenge : « La messagerie souveraine de l'administration » (Document limité à 2 pages)*

---

## 1. Modèle de Menaces Prises en Compte (Threat Model)

Dans le contexte des communications de l'administration publique burkinabè, FASO-SÉCUR prend en compte six menaces critiques :

| ID | Menace identifiée | Acteur menaçant | Impact potentiel |
| :--- | :--- | :--- | :--- |
| **M1** | **Compromission ou curiosité de l'hébergeur / BDD** : lecture de la base SQLite/PostgreSQL ou écoute du trafic sur le serveur. | Administrateur système malveillant, attaquant ayant obtenu un dump SQL. | Divulgation d'instructions ministérielles ou de notes confidentielles. |
| **M2** | **Vol ou perte du terminal d'un agent sur le terrain** ou départ d'un agent de son service. | Tiers en possession physique du téléphone/PC ou ancien agent non habilité. | Accès non autorisé aux conversations en cours et aux nouveaux messages. |
| **M3** | **Intrusion d'un compte non enrôlé** ou usurpation d'identité par vol de mot de passe simple. | Attaquant externe tentant de s'inscrire ou de deviner un mot de passe. | Infiltration d'un groupe de travail interministériel. |
| **M4** | **Analyse de trafic et corrélation des métadonnées** (qui parle à qui, à quelle seconde exacte, taille exacte des fichiers). | Observateur passif sur le serveur ou le réseau. | Cartographie de la chaîne de décision administrative. |
| **M5** | **Fuite visuelle ou transfert non autorisé** d'une note sensible (copier-coller, photo d'écran, partage). | Destinataire négligent ou indiscret. | Fuite d'un document classifié *Diffusion Restreinte* ou *Confidentiel*. |
| **M6** | **Répudiation d'une instruction officielle** (un agent affirme ne pas avoir reçu ou lu un ordre de service). | Agent interne de mauvaise foi. | Blocage administratif ou litige hiérarchique. |

---

## 2. Protections Cryptographiques et Architecturales Mises en Place

### 2.1. Chiffrement de Bout en Bout (Contre M1 — « Le serveur ne lit rien »)
- **Aucune cryptographie maison** : Utilisation exclusive des standards **W3C WebCrypto (`SubtleCrypto` — BoringSSL/NSS)** mettant en œuvre le modèle de session de groupe **Matrix Olm/Megolm & Signal X3DH**.
- **Chiffrement des messages, fichiers et notes vocales (`AES-256-GCM`)** : Tout contenu est chiffré dans le navigateur de l'émetteur avec une clé de 256 bits dérivée par `HKDF-SHA256 (RFC 5869)` et un vecteur d'initialisation aléatoire de 96 bits (`nonce_or_iv`). Même les noms de fichiers et les flux audio (Mooré, Dioula, Fulfulde, Français) sont chiffrés avant d'atteindre l'API FastAPI.
- **Garde-fou serveur actif** : Le serveur FastAPI rejette automatiquement avec un code `400 Bad Request` toute requête JSON qui contiendrait un champ `plaintext`.

### 2.2. Enrôlement Strict, Authentification Forte 2FA & RBAC (Contre M3)
- **Zéro inscription publique** : Seuls les matricules préalablement inscrits par un administrateur (`SUPER_ADMIN_DGTD` ou `POINT_FOCAL`) dans la table `enrolled_agents` peuvent s'authentifier. Toute tentative d'un compte non enrôlé déclenche un rejet `403 Forbidden` et une alerte critique dans `security_audit_logs`.
- **Double facteur obligatoire** :
  1. Mot de passe haché avec `bcrypt` (coût 12, salage unique par agent).
  2. Code **TOTP à 6 chiffres (RFC 6238)** vérifié côté serveur via `cryptography.hazmat.primitives.twofactor.totp.TOTP` (PyCA `cryptography`).

### 2.3. Révocation Immédiate, Remote Wipe & Rotation des Clés de Groupe (Contre M2)
Lorsqu'un administrateur révoque un agent (ex. perte d'appareil ou fin de mission) pendant une conversation :
1. **Invalidation instantanée des jetons** : `is_revoked` passe à `True` et `token_version` est incrémenté en base ; chaque requête REST ou WebSocket vérifie `token_version` en temps réel et rejette immédiatement l'agent (`403 Forbidden`).
2. **Effacement à distance (`REMOTE_WIPE_AND_REVOKE`)** : Le serveur pousse immédiatement une trame WebSocket prioritaire qui purge le `localStorage` et le `sessionStorage` du client révoqué (suppression des clés privées locales), puis ferme la connexion WebSocket avec le code `4003`.
3. **Retrait des salons & Rotation d'époque (`crypto_epoch`)** : L'agent est supprimé de `channel_members` et le compteur `crypto_epoch` de tous ses salons est incrémenté (`Epoch N -> N+1`). Les membres restants dérivent immédiatement une nouvelle clé de session Megolm `HKDF-SHA256`, rendant mathématiquement impossible le déchiffrement des nouveaux messages par l'appareil révoqué.

### 2.4. Protection des Documents Classifiés & Valeur Probante (Contre M5 & M6)
- **Filigrane dynamique dissuasif** : Les messages `DIFFUSION_RESTREINTE` et `CONFIDENTIEL` affichent en filigrane diagonal le matricule et le nom du lecteur courant, bloquent l'événement `onCopy` et désactivent l'impression CSS (`@media print`).
- **Floutage anti-regard & Expiration automatique** : Les messages `CONFIDENTIEL` sont floutés par défaut et peuvent être programmés pour une suppression automatique en base (`expires_at`).
- **Accusé de lecture signé (`ECDSA-SHA256`)** : L'agent destinataire signe avec sa clé privée `ECDSA P-256` le condensat `SHA-256` du message chiffré, produisant une preuve cryptographique vérifiable.

---

## 3. Métadonnées Visibles par le Serveur & Mesures de Minimisation (Contre M4)

Bien que le serveur ne puisse lire aucun contenu, un serveur de messagerie a techniquement besoin d'acheminer les paquets. Voici en toute transparence ce que le serveur voit et comment FASO-SÉCUR le réduit :

| Métadonnée technique | Ce qu'un serveur classique voit | Mesure de minimisation implémentée dans FASO-SÉCUR |
| :--- | :--- | :--- |
| **Contenu du message / fichier / nom de fichier** | Parfois visible ou indexé | **Totalement invisible** : `ciphertext_payload` opaque chiffré en `AES-256-GCM` côté client. |
| **Identité de l'émetteur dans les tables de messages et de blobs** | Matricule ou ID en clair dans les logs | **Pseudonymisation HMAC-SHA256** : stockage d'un condensat non réversible `pseudo_<hmac>` dans les enveloppes et journaux d'audit. |
| **Horodatage exact d'envoi** | Seconde et milliseconde exactes (corrélation temporelle) | **Time-Bucketing (Arrondi par tranche de 5 minutes)** : `timestamp_bucket` lisse les horodatages (`HH:00`, `HH:05`, `HH:10`). |
| **Taille exacte des pièces jointes et notes vocales** | Taille à l'octet près (empreinte de fichier) | **Padding par bloc de 4 096 octets** : `size_padded_bytes` masque la taille réelle du fichier ou de l'enregistrement vocal. |

---

## 4. Limites Connues & Perspectives d'Évolution

1. **Distribution initiale de la clé de salon en démonstration multi-onglets** : Pour permettre au jury de tester instantanément le prototype sur plusieurs navigateurs sans cérémonie manuelle d'échange de QR codes entre chaque paire d'agents, la dérivation de la clé de salon Megolm `HKDF-SHA256` utilise l'identifiant du salon et l'époque `crypto_epoch` distribuée uniquement aux membres authentifiés non révoqués. En déploiement de production nationale, l'échange de la clé de session Megolm s'effectue par encapsulage individuel `ECDH P-256 / X25519` sur la pré-clé signée (`signed_prekey_public`) de chaque membre.
2. **Limites du navigateur Web face aux captures d'écran matérielles** : Un navigateur web ne peut pas bloquer l'outil de capture de l'OS (contrairement à `FLAG_SECURE` sur Android) ni empêcher un tiers de photographier l'écran avec un second téléphone. Le filigrane dynamique nominatif et le floutage anti-regard assurent néanmoins la dissuasion et la traçabilité en cas de fuite.
3. **Stockage des clés privées dans le navigateur** : Les clés privées sont isolées dans le stockage local du navigateur et effacables à distance (`REMOTE_WIPE`). Une version mobile/desktop packagée (Tauri / Electron / Flutter) permettra de les sceller dans le *Secure Enclave / TPM* matériel.
