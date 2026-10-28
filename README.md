# 🇧🇫 FASO-SÉCUR — La Messagerie Souveraine de l'Administration
**Sprint Technique Pré-Hackathon 226 (Édition 2026) — MTDPCE / DGTD • Burkina Faso**  
*« Solutions open source endogènes »*

---

## 1. Concept & Niveau d'Engagement Open Source

**FASO-SÉCUR** est une messagerie instantanée souveraine, chiffrée de bout en bout (E2EE) et déployable en une seule commande sur l'infrastructure de l'État burkinabè (Cloud Gouvernemental / Datacenter DGTD). Elle permet aux agents publics d'échanger messages, instructions officielles, notes vocales en langues nationales et fichiers classifiés sans dépendre d'aucun service ni serveur tiers.

- **Niveau d'engagement Open Source déclaré** : **Créer & Étendre** — Application nouvelle publiée sous licence **MIT** ([`LICENSE`](./LICENSE)), reposant exclusivement sur des primitives cryptographiques standardisées et auditées.
- **Zéro dépendance externe** : Aucune API tierce (ni Firebase, ni CDN externe, ni service cloud privé) n'est requise.

---

## 2. Architecture & Protocole de Chiffrement de Bout en Bout (E2EE)

```
[Client React + W3C WebCrypto (ECDH P-256 / HKDF-SHA256 / AES-256-GCM / ECDSA P-256)]
       │  (Enveloppes chiffrées padées à 256 octets + Signatures ECDSA vérifiées)
       ▼
[Serveur Relais Zero-Knowledge (Python FastAPI + WebSockets)]
       │  (Authentification 2FA TOTP RFC 6238 chiffré Fernet + RBAC + Révocation Temps Réel)
       ▼
[Base Souveraine SQLite / PostgreSQL (Zéro texte ni secret en clair + Métadonnées minimisées)]
```

1. **Chiffrement de bout en bout (Client-Side E2EE)** : Protocole de session de groupe inspiré des principes d'échange de clés de Signal et de session de groupe de Matrix Megolm, assemblé exclusivement à partir des primitives natives auditées du standard **W3C Web Cryptography API** (`ECDH P-256`, `HKDF-SHA256 RFC 5869`, `AES-256-GCM`, `ECDSA P-256`). Un secret de groupe aléatoire de 256 bits (`CSPRNG`) est généré côté client à chaque époque et distribué aux membres par enveloppes `ECDH P-256`. Le module [`e2eeEngine.js`](./frontend/src/crypto/e2eeEngine.js) est isolé pour permettre le branchement direct de `@matrix-org/olm` / `vodozemac` (WASM) en production.
2. **Identité vérifiée, 2FA chiffré au repos & Numéros de sécurité** : Seuls les agents préalablement enrôlés par la DGTD peuvent se connecter après vérification de leur mot de passe (`bcrypt`) et de leur code **2FA TOTP (RFC 6238)** dont la graine est chiffrée au repos en base via **Fernet (`AES-128-CBC + HMAC-SHA256`)**. Chaque agent dispose d'un **Numéro de sécurité à 30 chiffres (`SHA-256`)** vérifiable hors-bande.
3. **Révocation immédiate & Rotation d'époque (`crypto_epoch`)** : La révocation d'un agent coupe instantanément ses WebSockets (`Code 4003`), déclenche un effacement à distance (`REMOTE_WIPE`) de son trousseau local, invalide ses JWT et incrémente `crypto_epoch` sur ses groupes afin de générer un nouveau secret de groupe aléatoire excluant l'agent révoqué.

---

## 3. Technologies Open Source Utilisées & Licences

| Composant | Technologie Open Source | Licence OSI | Lien Officiel du Projet |
| :--- | :--- | :--- | :--- |
| **Primitives E2EE Client** | W3C WebCrypto API (`SubtleCrypto` — BoringSSL/NSS) | W3C / BSD / ISC | https://www.w3.org/TR/WebCryptoAPI/ |
| **Backend API & Temps Réel** | FastAPI, Starlette & Uvicorn (Python) | MIT / BSD-3 | https://github.com/fastapi/fastapi |
| **Cryptographie Serveur (2FA, Fernet, ECDSA)** | PyCA `cryptography` | Apache-2.0 / BSD | https://github.com/pyca/cryptography |
| **Hachage Mots de Passe & Jetons JWT** | `bcrypt` & `PyJWT` | Apache-2.0 / MIT | https://github.com/pyca/bcrypt |
| **ORM & Base de Données** | SQLAlchemy & SQLite / PostgreSQL | MIT License | https://github.com/sqlalchemy/sqlalchemy |
| **Interface Utilisateur Web** | React 18, Vite, Tailwind CSS & Lucide Icons | MIT / ISC License | https://github.com/facebook/react |
| **Tests Automatisés Sécurité** | Pytest & Node.js Test Runner | MIT License | https://github.com/pytest-dev/pytest |

---

## 4. Installation Souveraine en Une Seule Commande

### Option A — Déploiement Souverain via Docker Compose (Recommandé)
```bash
docker compose up --build
```
- **Interface Web E2EE** : http://localhost:5173
- **API Souveraine & Documentation OpenAPI** : http://localhost:8000/docs

### Option B — Exécution Locale Directe & Tests Automatisés
```bash
# 1. Lancer les suites de tests automatisés de sécurité (Backend Pytest + Client WebCrypto)
cd backend && python -m pytest
node frontend/tests/test_e2ee_engine.mjs

# 2. Démarrer le serveur FastAPI en mode démo (Terminal 1)
cd backend && FASO_SECUR_DEMO_MODE=true python -m uvicorn main:app --host 127.0.0.1 --port 8000

# 3. Démarrer le client React (Terminal 2)
cd frontend && npm install && npm run dev
```

---

## 5. Comptes Fictifs de Démonstration pour le Jury

> **Note** : Lorsque `FASO_SECUR_DEMO_MODE=true` (actif dans `docker compose up`), l'écran de connexion affiche un **sélecteur rapide 1-clic** qui pré-remplit le matricule, le mot de passe et le code **2FA TOTP (RFC 6238)** courant pour faciliter les épreuves en direct du jury. En production (`FASO_SECUR_DEMO_MODE=false` par défaut), cet endpoint est désactivé.

| Matricule | Nom Fictif | Ministère / Direction | Rôle | Mot de passe | Secret 2FA Base32 (Initial) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `BF-DGTD-001` | Aminata OUÉDRAOGO | MTDPCE / DGTD | `SUPER_ADMIN_DGTD` | `FasoSecur!2026` | `JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXA` |
| `BF-MEFP-102` | Ibrahim SAWADOGO | MEFP / Trésor Public | `POINT_FOCAL` | `FasoSecur!2026` | `JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXB` |
| `BF-MATDS-204` | Moussa KABORÉ | MATDS / Territoire | `AGENT_PUBLIC` | `FasoSecur!2026` | `JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXC` |
| `BF-SANTE-308` | Fatimata DIALLO | MSHP / Santé | `AGENT_PUBLIC` | `FasoSecur!2026` | `JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXD` |
| `BF-MISSION-999` | Adama ZONGO | Mission Temporaire | `AGENT_PUBLIC` *(Cible Révocation)* | `FasoSecur!2026` | `JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXE` |

---

## 6. Fonctionnalités Innovantes & Limites Connues Documentées

- **Innovations intégrées** : Classification scellée dans le chiffré (`Ordinaire`, `Diffusion Restreinte` avec filigrane matricule, `Confidentiel` avec floutage anti-regard et auto-destruction), accusé de lecture signé à valeur probante (`ECDSA P-256`), interface et notes vocales E2EE en **Français, Mooré, Dioula et Fulfulde**, mode faible connexion, bouton d'urgence (`Panic Wipe`), Numéros de sécurité à 30 chiffres et inspecteur BDD/Réseau dynamique réservé aux administrateurs/auditeurs.
- **Limites connues du prototype** : Protection anti-capture d'écran logicielle (dissuasion par filigrane dynamique sur navigateur web, le blocage matériel nécessitant un conteneur OS natif), rotation de clé par époque de salon (sans ratchet symétrique message par message intra-époque), et vérification hors-bande des Numéros de sécurité requise contre un serveur activement compromis.
