# Guide de Contribution Open Source — FASO-SÉCUR 🇧🇫

Merci de contribuer à **FASO-SÉCUR**, la messagerie instantanée souveraine de l'administration publique du Burkina Faso. La distribution du projet est sous **GPL-3.0-only** (`LICENSE`) ; le code original conserve aussi une permission de réutilisation **MIT** (`LICENSE-MIT`). Les contributions doivent inclure leurs titulaires de droits et leur licence applicable.

---

## 1. Règles d'Or de Sécurité (Non Négociables)

1. **Aucune cryptographie « maison »** : Toutes les opérations cryptographiques doivent exclusivement utiliser :
   - **Côté Client** : la bibliothèque open source du **Protocole Signal** (`@privacyresearch/libsignal-protocol-typescript` — X3DH `Curve25519` / `Ed25519` + `Double Ratchet`) et les primitives natives **W3C Web Cryptography API (`window.crypto.subtle`)** (`ECDSA P-256`, `AES-256-GCM`).
   - **Côté Serveur** : la bibliothèque **`PyCA cryptography`** (`Fernet`, `TOTP` RFC 6238, vérification `ECDSA P-256`) et **`bcrypt`**.
2. **Zéro donnée en clair côté serveur (Sealed Sender)** : Aucune route FastAPI ni aucune colonne SQLAlchemy ne doit jamais recevoir ou stocker un message, un nom de fichier, l'identité de l'émetteur d'un message (`sender_id`) ou la classification en clair.
3. **Zéro service tiers** : Aucune dépendance vers une API externe, un CDN tiers ou un service cloud propriétaire n'est admise.

---

## 2. Exécution des Tests Automatisés Avant Tout Commit

Avant de soumettre une Pull Request, vérifiez que 100 % des suites de tests backend et frontend passent :

```bash
# 1. Suite de sécurité Backend (14 tests Pytest)
cd backend
python -m pytest -v

# 2. Suite de tests unitaires du moteur E2EE Client (Signal libsignal + WebCrypto Node.js - 9 tests)
cd ../frontend
npm test

# 3. Validation du build de production et découpage des modules (Rollup/Vite)
npm run build
```
