# NOTE DE PRÉ-PROJET — **FASO-SÉCUR**
**Sprint Technique Pré-Hackathon 226 (Édition 2026) — MTDPCE / DGTD • Burkina Faso**  
*Challenge : « La messagerie souveraine de l'administration » (Document limité à 2 pages)*

---

## 1. Concept & Vision Souveraine

Les agents de l'administration publique burkinabè échangent quotidiennement des instructions de service, notes techniques et informations sensibles sur des messageries grand public étrangères dont l'hébergement, les métadonnées et la gouvernance échappent totalement à l'État.

**FASO-SÉCUR** répond à cet enjeu stratégique par une plateforme de messagerie instantanée **100 % souveraine, open source et Zero-Knowledge** :
- **Maîtrise étatique totale** : Déployable en une seule commande (`docker compose up`) sur les serveurs du MTDPCE / DGTD sans aucune dépendance à un service tiers (zéro API externe).
- **Sécurité de bout en bout (E2EE) non négociable** : Le serveur agit comme un simple relais aveugle incapable de déchiffrer les messages, les notes vocales ou les pièces jointes.
- **Adaptée aux réalités du Burkina Faso** : Prise en compte de la hiérarchie ministérielle, de la valeur probante des instructions administratives, de l'inclusion linguistique (**Français, Mooré, Dioula, Fulfulde**) et des zones à faible couverture réseau.

---

## 2. Architecture Technique & Protocole de Chiffrement Retenu

### Architecture Globale (Client Lourd Cryptographique + Relais FastAPI Zero-Knowledge)
L'architecture sépare strictement le **plan de confiance cryptographique** (exécuté à 100 % sur le poste de l'agent dans le client React) et le **plan de routage et de contrôle d'accès** (assuré par le serveur Python FastAPI et sa base SQLite/PostgreSQL).

1. **Protocole de Chiffrement de Bout en Bout (Modèle Matrix Olm/Megolm & Signal X3DH)** :
   - Conformément à l'interdiction absolue de toute cryptographie développée par l'équipe, FASO-SÉCUR s'appuie exclusivement sur les primitives standardisées et auditées du **W3C Web Cryptography API (`SubtleCrypto` — BoringSSL/NSS)** :
     - **Identité & Signature (`ECDSA P-256 / SHA-256`)** : Chaque agent génère localement une paire de clés de signature et signe sa pré-clé publique ainsi que ses accusés de réception officiels.
     - **Accord de Clé & Ratchet de Groupe (`ECDH P-256` + `HKDF-SHA256 RFC 5869`)** : Chaque canal institutionnel possède une époque cryptographique (`crypto_epoch`). La clé de session `AES-256-GCM` est dérivée par `HKDF-SHA256`.
     - **Chiffrement Authentifié (`AES-256-GCM`)** : Chaque message texte, note vocale ou document joint est chiffré côté client avec un vecteur d'initialisation aléatoire de 96 bits (`nonce_or_iv`) et un tag d'authenticité de 128 bits avant tout transit réseau.
2. **Contrôle d'Accès, Identité Vérifiée & Révocation Temps Réel** :
   - **Enrôlement préalable obligatoire** : L'auto-inscription est désactivée ; tout compte non enrôlé par la DGTD est immédiatement rejeté (`403 Forbidden`) et tracé dans le journal d'audit.
   - **Second facteur 2FA TOTP (RFC 6238)** : Implémenté via la bibliothèque open source `PyCA cryptography`.
   - **Révocation immédiate** : En un clic, l'administrateur DGTD révoque un agent. Le serveur incrémente `token_version` (invalidant tous ses JWT), coupe ses sessions WebSocket avec l'ordre `REMOTE_WIPE_AND_REVOKE` (qui purge les clés locales de l'appareil) et incrémente `crypto_epoch` sur tous ses salons pour renouveler les clés de groupe.

---

## 3. Composants Open Source, Licences & Niveau d'Engagement

### Niveau d'engagement déclaré : **Créer & Étendre**
Le code source complet (serveur, client, scripts de déploiement et tests de sécurité) est publié sous **Licence MIT** (reconnue par l'OSI).

| Brique | Composant Open Source | Licence | Usage dans FASO-SÉCUR |
| :--- | :--- | :--- | :--- |
| **Cryptographie Client** | W3C WebCrypto API (`SubtleCrypto`) | W3C / BSD | Chiffrement E2EE `AES-256-GCM`, `HKDF-SHA256`, `ECDH/ECDSA P-256` |
| **Cryptographie Serveur** | `PyCA cryptography` & `bcrypt` | Apache-2.0 / BSD | Authentification forte 2FA TOTP (RFC 6238) et hachage de mots de passe |
| **Serveur & WebSockets** | `FastAPI`, `Uvicorn`, `PyJWT` | MIT / BSD-3 | Relais Zero-Knowledge, RBAC, révocation temps réel |
| **Persistance** | `SQLAlchemy` & `SQLite` / `PostgreSQL` | MIT | Stockage des blobs chiffrés et métadonnées pseudonymisées |
| **Client Web** | `React 18`, `Vite`, `Tailwind CSS`, `Lucide` | MIT / ISC | Interface multilingue (FR/Mooré/Dioula/Fulfulde) et enregistreur vocal E2EE |
| **Qualité & Audit** | `Pytest` | MIT | Suite de 5 tests automatisés validant les épreuves de sécurité |

---

## 4. Fonctionnalités Innovantes Pertinentes pour l'Administration Burkinabè

1. **Classification Officielle des Messages (`Ordinaire`, `Diffusion Restreinte`, `Confidentiel`)** :
   - *Diffusion Restreinte* : blocage de la copie/transfert et incrustation d'un **filigrane dynamique** affichant le matricule et le nom de l'agent lecteur pour dissuader toute prise de photo de l'écran.
   - *Confidentiel État* : **floutage anti-regard par défaut** (dévoilé uniquement au survol) et **auto-destruction programmable** (60 s, 5 min, 1 h).
2. **Accusé de Lecture à Valeur Probante pour les Instructions de Service** :
   - Permet au destinataire d'une instruction officielle de générer une **signature numérique `ECDSA-SHA256`** prouvant de manière non répudiable la prise de connaissance du document.
3. **Inclusion Linguistique Nationale (Français, Mooré, Dioula, Fulfulde) & Notes Vocales E2EE** :
   - Interface intégralement traduite dans les trois principales langues nationales en plus du français, accompagnée d'un module de **notes vocales chiffrées de bout en bout** pour les agents sur le terrain.
4. **Annuaire Officiel par Ministère & Fonction** :
   - Regroupement structuré par ministères (MTDPCE, MEFP, MATDS, MSHP…) avec vérification des clés publiques.
5. **Mode Dégradé « Faible Connexion » & Bouton d'Urgence (`Panic Wipe`)** :
   - File d'attente hors-ligne chiffrée pour les zones mal couvertes et bouton d'effacement d'urgence en cas de perte ou menace sur le terrain.
6. **Inspecteur Live « Le Serveur Ne Lit Rien »** :
   - Console intégrée permettant au jury d'inspecter en direct les tables SQL brutes du serveur et de constater l'absence totale de texte en clair.

---

## 5. Répartition des Rôles au sein de l'Équipe

- **Membre 1 (Architecture Backend & Sécurité Serveur)** : API FastAPI, authentification forte 2FA TOTP (RFC 6238), gestion des rôles RBAC, révocation temps réel WebSocket, minimisation des métadonnées HMAC et conteneurisation Docker Compose.
- **Membre 2 (Cryptographie Client E2EE & Tests Automatisés)** : Moteur de chiffrement de bout en bout (`e2eeEngine.js` — `AES-256-GCM`, `HKDF`, signatures probantes `ECDSA`), chiffrement des fichiers/notes vocales et suite de tests `pytest`.
- **Membre 3 (Interface Utilisateur, Ergonomie & Innovations Métier)** : Application React/Tailwind, niveaux de classification administrative, filigrane dynamique, traduction en langues nationales (Mooré, Dioula, Fulfulde) et documentation technique.
