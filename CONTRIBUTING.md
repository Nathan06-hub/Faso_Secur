# Guide de Contribution Open Source — FASO-SÉCUR 🇧🇫

Merci de contribuer à **FASO-SÉCUR**, la messagerie instantanée souveraine de l'administration publique du Burkina Faso, publiée sous licence **MIT**.

---

## 1. Règles d'Or de Sécurité (Non Négociables)

1. **Aucune cryptographie « maison »** : Toutes les opérations cryptographiques doivent exclusivement utiliser :
   - **Côté Client** : le standard **W3C Web Cryptography API (`window.crypto.subtle`)** (`ECDH P-256`, `ECDSA P-256`, `HKDF-SHA256`, `AES-256-GCM`).
   - **Côté Serveur** : la bibliothèque **`PyCA cryptography`** et **`bcrypt`**.
2. **Zéro donnée en clair côté serveur (Sealed Sender)** : Aucune route FastAPI ni aucune colonne SQLAlchemy ne doit jamais recevoir ou stocker un message, un nom de fichier, l'identité de l'émetteur d'un message (`sender_id`) ou la classification en clair.
3. **Zéro service tiers** : Aucune dépendance vers une API externe, un CDN tiers ou un service cloud propriétaire n'est admise.

---

## 2. Exécution des Tests Automatisés Avant Tout Commit

Avant de soumettre une Pull Request, vérifiez que 100 % des suites de tests backend et frontend passent :

```bash
# 1. Suite de sécurité Backend (7 tests Pytest)
cd backend
python -m pytest

# 2. Suite de tests unitaires du moteur E2EE Client (WebCrypto Node.js)
cd ../frontend
node tests/test_e2ee_engine.mjs
```
