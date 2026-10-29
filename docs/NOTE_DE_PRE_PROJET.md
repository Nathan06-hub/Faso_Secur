# NOTE DE PRÉ-PROJET — **FASO-SÉCUR**
**Sprint Technique Pré-Hackathon 226 (Édition 2026) — MTDPCE / DGTD • Burkina Faso**  
*Challenge : « La messagerie souveraine de l'administration » (Document limité à 2 pages)*

---

## 1. Concept & Vision Souveraine

Les agents de l'administration publique burkinabè échangent quotidiennement des instructions de service, notes techniques et informations sensibles sur des messageries grand public étrangères dont l'hébergement, les métadonnées et la gouvernance échappent totalement à l'État.

**FASO-SÉCUR** répond à cet enjeu stratégique par une plateforme de messagerie instantanée **100 % souveraine, open source et Zero-Knowledge** :
- **Maîtrise étatique totale** : Déployable en une seule commande (`docker compose up --build`) sur les serveurs du MTDPCE / DGTD sans aucune dépendance à un service tiers (zéro API externe), avec support natif de la terminaison HTTPS / TLS 1.3 (`docker-compose.tls.yml`).
- **Sécurité de bout en bout (E2EE) non négociable** : Le serveur agit comme un simple relais aveugle incapable de déchiffrer les messages, les notes vocales ou les pièces jointes.
- **Adaptée aux réalités du Burkina Faso** : Prise en compte de la hiérarchie ministérielle, de la valeur probante des instructions administratives, de l'inclusion linguistique (**Français, Mooré, Dioula, Fulfulde**) et des zones à faible couverture réseau.

---

## 2. Architecture Technique & Protocole de Chiffrement Retenu (Signal / libsignal)

### Architecture Globale (Client Lourd Cryptographique + Relais FastAPI Zero-Knowledge)
L'architecture sépare strictement le **plan de confiance cryptographique** (exécuté à 100 % sur le poste de l'agent dans le client React) et le **plan de routage et de contrôle d'accès** (assuré par le serveur Python FastAPI et sa base SQLite/PostgreSQL).

1. **Protocole de Chiffrement de Bout en Bout (Signal Protocol via `@privacyresearch/libsignal-protocol-typescript` + W3C WebCrypto)** :
   - Conformément au règlement du sprint qui impose l'usage d'un protocole éprouvé sans aucune primitive cryptographique maison, FASO-SÉCUR intègre la bibliothèque open source **`@privacyresearch/libsignal-protocol-typescript` (`libsignal`)** combinée aux primitives natives du **W3C Web Cryptography API (`SubtleCrypto` — BoringSSL/NSS)** :
     - **Accord de Clé X3DH & Pré-clés à usage unique consommables (`KeyHelper`, `SessionBuilder`, `SessionCipher`)** : Lors de l'initialisation du trousseau ([`e2eeEngine.js`](../frontend/src/crypto/e2eeEngine.js)), chaque agent génère son `registrationId`, sa paire de clés d'identité `Curve25519`, sa pré-clé signée `Ed25519` (`SignedPreKey`) et un lot de **20 pré-clés à usage unique (`One-Time PreKeys`)**. Chaque pré-clé utilisée lors d'un `PreKeyWhisperMessage` (type 3) est consommée et supprimée côté serveur (`/api/e2ee/prekeys/consume/{matricule}`) et côté client (`removePreKey`). L'état complet du `SignalProtocolStore` est chiffré au repos par une clé maîtresse `AES-256-GCM` **non-extractible (`extractable: false`)** stockée dans `IndexedDB`.
     - **Chiffrement des Messages Directs et de Groupe par Sessions Signal Pair-à-Pair** : `@privacyresearch/libsignal-protocol-typescript` ne fournissant pas de primitive *Sender Key* de groupe, chaque message de salon (bourré par blocs de **256 octets**) est chiffré séparément pour chaque membre actif autorisé via sa session **Signal pair-à-pair** (`SessionBuilder.processPreKey` + `SessionCipher.encrypt`, produisant un `PreKeyWhisperMessage` type 3 puis des `WhisperMessage` type 1). Tout repli vers l'ancien schéma HKDF WebCrypto est supprimé et bloqué côté serveur (`HTTP 400`) et client (anti-downgrade).
     - **Pièces Jointes & Notes Vocales E2EE** : Chaque fichier binaire (bourré à **4 096 octets**) est chiffré côté client avec une **clé symétrique aléatoire fraîche `AES-256-GCM` (256 bits)** téléversée sans clé sur `/api/blobs`, puis la clé aléatoire `attachmentKeyB64` est distribuée exclusivement dans les enveloppes Signal pair-à-pair des membres autorisés. L'enveloppe globale est signée avec la clé **`ECDSA P-256`** certifiée dans l'annuaire.
2. **Contrôle d'Accès, Identité Vérifiée, Séparation des Secrets & Révocation Temps Réel** :
   - **Enrôlement préalable obligatoire** : L'auto-inscription est désactivée ; tout compte non enrôlé par la DGTD est immédiatement rejeté (`403 Forbidden`) et tracé dans le journal d'audit.
   - **Second facteur 2FA TOTP (RFC 6238) chiffré au repos & Secrets séparés** : Implémenté via `PyCA cryptography`, avec chiffrement au repos des secrets TOTP en base de données via **Fernet (`AES-128-CBC + HMAC-SHA256`)**. Les secrets serveur (`jwt_secret`, `metadata_pepper`, `totp_fernet_key`) sont persistés dans un volume dédié (`/app/secrets`) ou injectés via **Docker Secrets (`*_FILE`)**, séparés du volume de base de données (`/app/data`).
   - **Révocation immédiate** : En un clic, l'administrateur DGTD révoque un agent. Le serveur incrémente `token_version` (invalidant tous ses JWT), retire l'agent des salons, incrémente `crypto_epoch` (excluant l'agent révoqué des enveloppes Signal suivantes) et envoie l'ordre WebSocket `REMOTE_WIPE_AND_REVOKE`.

---

## 3. Composants Open Source, Licences & Compatibilité Juridique

### Niveau d'engagement déclaré : **Créer & Étendre**
La distribution FASO-SÉCUR et le paquet frontend sont déclarés sous **GPL-3.0-only** ([`LICENSE`](../LICENSE)). Le code original de l'équipe est également proposé sous **MIT** ([`LICENSE-MIT`](../LICENSE-MIT)). Les bibliothèques tierces gardent leurs licences propres, détaillées dans [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md). Toute autre stratégie de redistribution doit être validée avant publication.

| Brique | Composant Open Source | Licence | Usage dans FASO-SÉCUR |
| :--- | :--- | :--- | :--- |
| **Protocole Signal Client** | `@privacyresearch/libsignal-protocol-typescript` | **GPL-3.0-only** | Accord de clé X3DH (`SessionBuilder`), Double Ratchet (`SessionCipher`) et clés `Curve25519`/`Ed25519` |
| **Primitives WebCrypto** | W3C WebCrypto API (`SubtleCrypto`) | W3C / BSD | Clé maîtresse non-extractible `IndexedDB`, `AES-256-GCM`, signatures `ECDSA P-256` |
| **Cryptographie Serveur** | `PyCA cryptography` & `bcrypt` | Apache-2.0 / BSD | 2FA TOTP (RFC 6238), chiffrement Fernet au repos, vérification ECDSA et hachage `bcrypt` |
| **Serveur & WebSockets** | `FastAPI`, `Uvicorn`, `PyJWT` | MIT / BSD-3 | Relais Zero-Knowledge, RBAC, révocation temps réel et rejet anti-downgrade |
| **Persistance & Proxy TLS** | `SQLAlchemy` / `SQLite` & `Caddy 2` | MIT / Apache-2.0 | Stockage des blobs chiffrés, séparation des secrets et terminaison HTTPS / TLS 1.3 |
| **Frameworks UI & Tests** | `React 18`, `Vite`, `Tailwind`, `Pytest` | MIT / ISC | Frameworks et outils utilisés par l'application, déclarée GPL-3.0-only |

---

## 4. Fonctionnalités Innovantes & Répartition des Rôles

1. **Classification Officielle Scellée dans le Chiffré (`Ordinaire`, `Diffusion Restreinte` avec filigrane matricule, `Confidentiel` avec floutage anti-regard et auto-destruction)**.
2. **Accusé de Lecture à Valeur Probante (`ECDSA P-256`)** vérifié mathématiquement contre la clé publique d'annuaire.
3. **Inclusion Linguistique Nationale (Français, Mooré, Dioula, Fulfulde) & Notes Vocales E2EE**.
4. **Annuaire Officiel par Ministère, Numéros de Sécurité à 30 Chiffres, Mode Faible Connexion, `Panic Wipe` & Inspecteur BDD Dynamique**.
- **Répartition des rôles** : **Membre 1** (Backend FastAPI, 2FA TOTP Fernet, RBAC, Révocation, TLS) • **Membre 2** (Intégration `libsignal` X3DH + Double Ratchet pair-à-pair, chiffrement des pièces jointes, tests automatisés) • **Membre 3** (Interface React/Tailwind, classification administrative, langues nationales, documentation).
