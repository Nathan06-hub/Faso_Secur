# 🇧🇫 FASO-SÉCUR — La Messagerie Souveraine de l'Administration
**Sprint Technique Pré-Hackathon 226 (Édition 2026) — MTDPCE / DGTD • Burkina Faso**  
*« Solutions open source endogènes »*

---

## 1. Concept & Niveau d'Engagement Open Source

**FASO-SÉCUR** est une messagerie instantanée souveraine, chiffrée de bout en bout (E2EE) et hébergeable en une seule commande sur l'infrastructure de l'État burkinabè (Cloud Gouvernemental / Datacenter DGTD). Elle permet aux agents publics d'échanger messages, instructions officielles, notes vocales en langues nationales et fichiers classifiés sans dépendre d'aucun service ni serveur tiers.

- **Niveau d'engagement Open Source déclaré** : **Créer & Étendre** — Application nouvelle publiée sous licence **MIT** (fichier [`LICENSE`](./LICENSE) à la racine), reposant exclusivement sur des briques et protocoles cryptographiques open source éprouvés.
- **Zéro dépendance externe** : Aucune API tierce (ni Firebase, ni CDN externe, ni service cloud privé) n'est requise.

---

## 2. Architecture & Protocole de Chiffrement de Bout en Bout (E2EE)

```
[Client React + W3C WebCrypto (Olm/Megolm & Signal X3DH)]
       │  (Enveloppes strictement chiffrées AES-256-GCM + Signatures ECDSA-P256)
       ▼
[Serveur Relais Zero-Knowledge (Python FastAPI + WebSockets)]
       │  (Authentification 2FA TOTP RFC 6238 + RBAC + Révocation Temps Réel)
       ▼
[Base Souveraine SQLite / PostgreSQL (Zéro texte en clair + Métadonnées hachées HMAC)]
```

1. **Chiffrement de bout en bout (Client-Side E2EE)** : Implémentation du modèle de session de groupe **Matrix Olm/Megolm & Signal X3DH** via les primitives natives auditées du standard **W3C Web Cryptography API** (`ECDH P-256`, `HKDF-SHA256 RFC 5869`, `AES-256-GCM`, `ECDSA-SHA256`). Aucune cryptographie « maison » n'est utilisée.
2. **Identité vérifiée & 2FA obligatoire** : Seuls les agents préalablement enrôlés par la DGTD peuvent se connecter, après vérification de leur mot de passe (`bcrypt`) et de leur second facteur **TOTP (RFC 6238)** via `PyCA cryptography`.
3. **Révocation immédiate & Rotation d'époque (`crypto_epoch`)** : La révocation d'un agent coupe instantanément ses WebSockets (`Code 4003`), déclenche un effacement à distance (`REMOTE_WIPE`) de son trousseau local, invalide ses JWT et fait tourner l'époque cryptographique (`crypto_epoch`) de tous ses groupes.

---

## 3. Technologies Open Source Utilisées & Licences

| Composant | Technologie Open Source | Licence OSI | Lien Officiel du Projet |
| :--- | :--- | :--- | :--- |
| **Protocole & Primitives E2EE** | W3C WebCrypto (BoringSSL/NSS) — Modèle Matrix Olm/Megolm | W3C / BSD / ISC | https://www.w3.org/TR/WebCryptoAPI/ |
| **Backend API & Temps Réel** | FastAPI & Starlette (Python) | MIT License | https://github.com/fastapi/fastapi |
| **Serveur ASGI & WebSockets** | Uvicorn & `websockets` | BSD-3-Clause | https://github.com/encode/uvicorn |
| **Cryptographie 2FA TOTP (RFC 6238)** | PyCA `cryptography` | Apache-2.0 / BSD | https://github.com/pyca/cryptography |
| **Hachage Mots de Passe** | `bcrypt` (Python) | Apache-2.0 | https://github.com/pyca/bcrypt |
| **Jetons d'Accès Signés** | `PyJWT` | MIT License | https://github.com/jpadilla/pyjwt |
| **ORM & Base de Données** | SQLAlchemy & SQLite / PostgreSQL | MIT License | https://github.com/sqlalchemy/sqlalchemy |
| **Interface Utilisateur Web** | React 18 & Vite | MIT License | https://github.com/facebook/react |
| **Design & Icônes** | Tailwind CSS & Lucide Icons | MIT / ISC License | https://github.com/tailwindlabs/tailwindcss |
| **Tests Automatisés Sécurité** | Pytest | MIT License | https://github.com/pytest-dev/pytest |

---

## 4. Installation Souveraine en Une Seule Commande

### Option A — Déploiement Souverain via Docker Compose (Recommandé)
```bash
docker compose up --build
```
- **Interface Web E2EE** : http://localhost:5173
- **API Souveraine & Documentation OpenAPI** : http://localhost:8000/docs

### Option B — Exécution Locale Directe (Développement & Tests)
```bash
# 1. Lancer la suite de tests automatisés de sécurité (+2 pts Bonus)
cd backend && python -m pytest

# 2. Démarrer le serveur FastAPI (Terminal 1)
cd backend && python -m uvicorn main:app --host 127.0.0.1 --port 8000

# 3. Démarrer le client React (Terminal 2)
cd frontend && npm install && npm run dev
```

---

## 5. Comptes Fictifs de Démonstration pour le Jury

> **Note** : Sur l'écran de connexion, un **sélecteur rapide 1-clic** pré-remplit automatiquement le matricule, le mot de passe et le code **2FA TOTP (RFC 6238)** courant pour faciliter les épreuves en direct du jury.

| Matricule | Nom Fictif | Ministère / Direction | Rôle | Mot de passe | Secret 2FA Base32 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `BF-DGTD-001` | Aminata OUÉDRAOGO | MTDPCE / DGTD | `SUPER_ADMIN_DGTD` | `FasoSecur!2026` | `JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXA` |
| `BF-MEFP-102` | Ibrahim SAWADOGO | MEFP / Trésor Public | `POINT_FOCAL` | `FasoSecur!2026` | `JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXB` |
| `BF-MATDS-204` | Moussa KABORÉ | MATDS / Territoire | `AGENT_PUBLIC` | `FasoSecur!2026` | `JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXC` |
| `BF-SANTE-308` | Fatimata DIALLO | MSHP / Santé | `AGENT_PUBLIC` | `FasoSecur!2026` | `JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXD` |
| `BF-MISSION-999` | Adama ZONGO | Mission Temporaire | `AGENT_PUBLIC` *(Cible Révocation)* | `FasoSecur!2026` | `JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXE` |

---

## 6. Fonctionnalités Innovantes & Limites Connues

- **Innovations intégrées** : Classification (`Ordinaire`, `Diffusion Restreinte` avec filigrane matricule, `Confidentiel` avec floutage anti-regard et auto-destruction), accusé de lecture signé à valeur probante (`ECDSA-SHA256`), interface et notes vocales E2EE en **Français, Mooré, Dioula et Fulfulde**, mode faible connexion, bouton d'urgence (`Panic Wipe`) et inspecteur BDD/Réseau en direct pour le jury.
- **Limites connues du prototype** : Protection anti-capture d'écran logicielle (dissuasion par filigrane dynamique et floutage sur navigateur web, le blocage matériel nécessitant un conteneur OS natif), et dérivation d'époque Megolm simplifiée pour la démonstration multi-onglets.
