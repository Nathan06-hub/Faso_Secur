# NOTE DE PRÉ-PROJET — **FASO-SÉCUR**
**Sprint Technique Pré-Hackathon 226 (Édition 2026) — MTDPCE / DGTD • Burkina Faso**  
*Challenge : « La messagerie souveraine de l'administration » (Document de synthèse — Format 2 pages)*

---

### 1. Concept, Vision Souveraine & Innovation Métier

Les agents de l'administration burkinabè échangent quotidiennement des informations sensibles sur des plateformes grand public étrangères échappant au contrôle de l'État.  
**FASO-SÉCUR** apporte une réponse étatique souveraine, 100 % Zero-Knowledge et taillée pour les exigences administratives :
- **Déploiement Souverain en une commande** : `docker compose up --build` sans aucun service tiers (zéro cloud externe), avec support natif HTTPS / TLS 1.3 Caddy (`docker-compose.tls.yml`).
- **Moteur d'Instructions Officielles (`INST-2026-XXXX`)** : Tableau de bord dédié transformant les messages de service en directives administratives formelles avec suivi nominatif d'émargement et accusés probants signés en ECDSA P-256.
- **Enrôlement Moderne par QR Code & Caméra** : Génération de QR codes d'invitation à usage unique et lecteur caméra intégré pour activation instantanée sur smartphone.
- **Inclusion Nationale & Résilience** : Interface et messages vocaux chiffrés E2EE en **Français, Mooré, Dioula et Fulfulde** (+3 pts bonus), mode dégradé hors-ligne et bouton d'urgence `Panic Wipe`.

---

### 2. Architecture Technique & Protocole de Chiffrement Signal (libsignal)

L'architecture sépare strictement le **plan de confiance cryptographique** (exécuté à 100 % côté client dans le navigateur) et le **plan de routage Zero-Knowledge** (relais FastAPI et base de données SQLite/PostgreSQL).

1. **Protocole de Chiffrement E2EE Autorisé (Signal Protocol)** :
   - Conformément au règlement interdisant toute cryptographie maison, FASO-SÉCUR intègre l'implémentation open source officielle du **Protocole Signal** (`@privacyresearch/libsignal-protocol-typescript`) sur primitives natives W3C WebCrypto :
     - **Accord de Clés X3DH & Pré-clés à usage unique consommables** : Lot initial de 20 `One-Time PreKeys` par agent. Chaque pré-clé est réservée et consommée atomiquement côté serveur (`/api/e2ee/prekeys/consume`) et supprimée du trousseau local pour garantir le Forward Secrecy.
     - **Chiffrement des Échanges Directs et de Groupe par Sessions Signal Pair-à-Pair** : Chaque message (bourré à un multiple de 256 octets) est chiffré individuellement pour chaque membre actif autorisé via sa session Signal (`PreKeyWhisperMessage` puis `WhisperMessage`). Tout repli vers un chiffrement non approuvé est bloqué par contrôle anti-downgrade strict (HTTP 400).
     - **Pièces Jointes & Notes Vocales Chiffrées** : Le fichier (bourré à 4 096 octets) est chiffré en `AES-256-GCM` avec une clé symétrique aléatoire fraîche téléversée sans clé sur `/api/blobs`. La clé est distribuée exclusivement dans les enveloppes Signal des membres autorisés.
2. **Contrôle d'Accès, 2FA TOTP Fernet & Révocation Immédiate** :
   - **Enrôlement préalable obligatoire** : Aucune auto-inscription. Rejet systématique de tout intrus (`403 Forbidden`).
   - **Second facteur 2FA TOTP (RFC 6238)** : Graines 2FA chiffrées au repos par Fernet (`AES-128-CBC + HMAC-SHA256`). Les secrets serveur sont isolés dans un volume dédié (`/app/secrets`), séparé des données (`/app/data`).
   - **Révocation en direct** : Invalidation immédiate du jeton (`token_version`), coupure WebSocket temps réel, rotation d'époque (`crypto_epoch`) et ordre d'effacement local des clés (`REMOTE_WIPE`).

---

### 3. Composants Open Source & Licences

**Niveau d'engagement déclaré : Créer & Étendre** (application souveraine neuve bâtie sur la bibliothèque éprouvée Signal).  
La distribution globale et le paquet frontend sont régis par la licence **GNU GPL-3.0-only** ([`LICENSE`](../LICENSE)), assurant une conformité copyleft parfaite avec `@privacyresearch/libsignal-protocol-typescript`. Les notices détaillées figurent dans [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).

| Brique Logicielle | Composant Open Source | Licence | Rôle dans FASO-SÉCUR |
| :--- | :--- | :--- | :--- |
| **Protocole Signal** | `@privacyresearch/libsignal-protocol-typescript` | **GPL-3.0-only** | Accord de clé X3DH, Double Ratchet, clés Curve25519/Ed25519 |
| **Primitives WebCrypto** | W3C Web Cryptography API (`SubtleCrypto`) | Standard W3C | AES-256-GCM, hachage SHA-256, signatures ECDSA P-256 |
| **Cryptographie Serveur**| `PyCA cryptography` & `bcrypt` | Apache-2.0 / BSD | 2FA TOTP (RFC 6238), chiffrement Fernet au repos, hachage salé |
| **Serveur & WebSockets** | `FastAPI`, `Uvicorn`, `PyJWT` | MIT / BSD-3 | Relais Zero-Knowledge, contrôle RBAC, révocation en direct |
| **Persistance & TLS** | `SQLAlchemy` / `SQLite` & `Caddy 2` | MIT / Apache-2.0 | Stockage chiffré, découplage des secrets, terminaison TLS 1.3 |

---

### 4. Répartition des Rôles de l'Équipe

- **Membre 1 (Chef de projet & Backend)** : Architecture FastAPI, 2FA TOTP Fernet, RBAC ministériel, révocation temps réel, packaging Docker et TLS.
- **Membre 2 (Cryptographie & Sécurité)** : Sessions Signal X3DH + Double Ratchet pair-à-pair, gestion des pré-clés, chiffrement des pièces jointes, tests automatisés (19 tests pytest).
- **Membre 3 (Frontend & Innovation Métier)** : Interface React/Tailwind, moteur des instructions officielles, scan QR code, accusés probants ECDSA P-256 et langues nationales.
