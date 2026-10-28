# NOTE DE PRÉ-PROJET — **FASO-SÉCUR**
**Sprint Technique Pré-Hackathon 226 (Édition 2026) — MTDPCE / DGTD • Burkina Faso**  
*Challenge : « La messagerie souveraine de l'administration » (Document limité à 2 pages)*

---

## 1. Concept & Vision Souveraine

Les agents de l'administration publique burkinabè échangent quotidiennement des instructions de service, notes techniques et informations sensibles sur des messageries grand public étrangères dont l'hébergement, les métadonnées et la gouvernance échappent totalement à l'État.

**FASO-SÉCUR** répond à cet enjeu stratégique par une plateforme de messagerie instantanée **100 % souveraine, open source et Zero-Knowledge** :
- **Maîtrise étatique totale** : Déployable en une seule commande (`docker compose up --build`) sur les serveurs du MTDPCE / DGTD sans aucune dépendance à un service tiers (zéro API externe).
- **Sécurité de bout en bout (E2EE) non négociable** : Le serveur agit comme un simple relais aveugle incapable de déchiffrer les messages, les notes vocales ou les pièces jointes.
- **Adaptée aux réalités du Burkina Faso** : Prise en compte de la hiérarchie ministérielle, de la valeur probante des instructions administratives, de l'inclusion linguistique (**Français, Mooré, Dioula, Fulfulde**) et des zones à faible couverture réseau.

---

## 2. Architecture Technique & Protocole de Chiffrement Retenu

### Architecture Globale (Client Lourd Cryptographique + Relais FastAPI Zero-Knowledge)
L'architecture sépare strictement le **plan de confiance cryptographique** (exécuté à 100 % sur le poste de l'agent dans le client React) et le **plan de routage et de contrôle d'accès** (assuré par le serveur Python FastAPI et sa base SQLite/PostgreSQL).

1. **Protocole de Chiffrement de Bout en Bout (Inspiré de Signal & Matrix Megolm sur W3C WebCrypto)** :
   - Sans aucune primitive cryptographique développée par l'équipe, FASO-SÉCUR met en œuvre un protocole de session de groupe inspiré des principes d'échange de clés de Signal et de session de groupe de Matrix Megolm, assemblé exclusivement à partir des primitives standardisées et auditées du **W3C Web Cryptography API (`SubtleCrypto` — BoringSSL/NSS)** :
     - **Identité, Signature & Numéro de Sécurité (`ECDSA P-256 / SHA-256`)** : Chaque agent génère localement une paire de clés de signature, signe sa pré-clé publique ainsi que chaque enveloppe et accusé de réception officiel, et obtient un **Numéro de sécurité à 30 chiffres (`SHA-256`)** vérifiable hors-bande.
     - **Secret de Groupe Aléatoire & Encapsulage Pair-à-Pair (`ECDH P-256` + `HKDF-SHA256 RFC 5869`)** : À chaque époque cryptographique (`crypto_epoch`) d'un salon, un secret maître aléatoire de 256 bits (`CSPRNG`) est généré côté client et encapsulé individuellement pour chaque membre actif via un accord `ECDH P-256` + `HKDF-SHA256` + `AES-256-GCM`. Le module [`e2eeEngine.js`](../frontend/src/crypto/e2eeEngine.js) est isolé pour permettre le remplacement direct par `@matrix-org/olm` ou `vodozemac` (WASM) en production.
     - **Chiffrement Authentifié & Bourrage (`AES-256-GCM`)** : Chaque message (bourré par blocs de 256 octets) et chaque pièce jointe ou note vocale (bourrée par blocs de 4 096 octets) est chiffré côté client avec un IV aléatoire de 96 bits (`nonce_or_iv`) et un tag d'authenticité de 128 bits.
2. **Contrôle d'Accès, Identité Vérifiée & Révocation Temps Réel** :
   - **Enrôlement préalable obligatoire** : L'auto-inscription est désactivée ; tout compte non enrôlé par la DGTD est immédiatement rejeté (`403 Forbidden`) et tracé dans le journal d'audit.
   - **Second facteur 2FA TOTP (RFC 6238) chiffré au repos** : Implémenté via `PyCA cryptography`, avec chiffrement au repos des secrets TOTP en base de données via **Fernet (`AES-128-CBC + HMAC-SHA256`)**.
   - **Révocation immédiate** : En un clic, l'administrateur DGTD révoque un agent. Le serveur incrémente `token_version` (invalidant tous ses JWT), coupe ses sessions WebSocket avec l'ordre `REMOTE_WIPE_AND_REVOKE` (qui purge les clés locales de l'appareil) et incrémente `crypto_epoch` sur tous ses salons pour déclencher le renouvellement du secret de groupe.

---

## 3. Composants Open Source, Licences & Niveau d'Engagement

### Niveau d'engagement déclaré : **Créer & Étendre**
Le code source complet (serveur, client, scripts de déploiement et tests de sécurité) est publié sous **Licence MIT** (reconnue par l'OSI).

| Brique | Composant Open Source | Licence | Usage dans FASO-SÉCUR |
| :--- | :--- | :--- | :--- |
| **Cryptographie Client** | W3C WebCrypto API (`SubtleCrypto`) | W3C / BSD | Chiffrement E2EE `AES-256-GCM`, `HKDF-SHA256`, `ECDH/ECDSA P-256` |
| **Cryptographie Serveur** | `PyCA cryptography` & `bcrypt` | Apache-2.0 / BSD | 2FA TOTP (RFC 6238), chiffrement Fernet au repos, vérification ECDSA et hachage `bcrypt` |
| **Serveur & WebSockets** | `FastAPI`, `Uvicorn`, `PyJWT` | MIT / BSD-3 | Relais Zero-Knowledge, RBAC, révocation temps réel |
| **Persistance** | `SQLAlchemy` & `SQLite` / `PostgreSQL` | MIT | Stockage des blobs chiffrés et métadonnées pseudonymisées |
| **Client Web** | `React 18`, `Vite`, `Tailwind CSS`, `Lucide` | MIT / ISC | Interface multilingue (FR/Mooré/Dioula/Fulfulde) et enregistreur vocal E2EE |
| **Qualité & Audit** | `Pytest` & `Node.js assert` | MIT | Suites de tests automatisés validant les épreuves de sécurité serveur et client |

---

## 4. Fonctionnalités Innovantes Pertinentes pour l'Administration Burkinabè

1. **Classification Officielle Scellée dans le Chiffré (`Ordinaire`, `Diffusion Restreinte`, `Confidentiel`)** :
   - La classification et les drapeaux de protection (`noForward`, `antiScreenshot`) sont chiffrés à l'intérieur du `ciphertext_payload` (invisibles pour le serveur).
   - *Diffusion Restreinte* : blocage de la copie et incrustation d'un **filigrane dynamique** affichant le matricule et le nom du lecteur.
   - *Confidentiel État* : **floutage anti-regard par défaut** (dévoilé au survol) et **auto-destruction programmable** (60 s, 5 min, 1 h).
2. **Accusé de Lecture à Valeur Probante pour les Instructions de Service** :
   - Permet au destinataire d'une instruction officielle de générer une **signature numérique `ECDSA P-256`** vérifiée mathématiquement contre la clé publique de l'annuaire.
3. **Inclusion Linguistique Nationale (Français, Mooré, Dioula, Fulfulde) & Notes Vocales E2EE** :
   - Interface intégralement traduite dans les trois principales langues nationales en plus du français, accompagnée d'un module de **notes vocales chiffrées de bout en bout**.
4. **Annuaire Officiel par Ministère & Numéros de Sécurité à 30 Chiffres** :
   - Regroupement par ministères (MTDPCE, MEFP, MATDS, MSHP…) avec affichage de l'empreinte cryptographique à 30 chiffres de chaque agent.
5. **Mode Dégradé « Faible Connexion », Bouton d'Urgence (`Panic Wipe`) & Inspecteur BDD Dynamique** :
   - File d'attente hors-ligne chiffrée, effacement local d'urgence et console d'inspection SQL dynamique réservée aux administrateurs/auditeurs.

---

## 5. Répartition des Rôles au sein de l'Équipe

- **Membre 1 (Architecture Backend & Sécurité Serveur)** : API FastAPI, authentification forte 2FA TOTP (RFC 6238) chiffré Fernet, RBAC, révocation temps réel WebSocket, minimisation des métadonnées HMAC et conteneurisation Docker Compose.
- **Membre 2 (Cryptographie Client E2EE & Tests Automatisés)** : Moteur de chiffrement de bout en bout (`e2eeEngine.js` — `ECDH P-256`, `AES-256-GCM`, `HKDF`, signatures probantes `ECDSA`), chiffrement des fichiers/notes vocales et suites de tests automatisés.
- **Membre 3 (Interface Utilisateur, Ergonomie & Innovations Métier)** : Application React/Tailwind, niveaux de classification administrative, filigrane dynamique, traduction en langues nationales (Mooré, Dioula, Fulfulde) et documentation technique.
