# Journal des Modifications (CHANGELOG) — FASO-SÉCUR

Toutes les évolutions notables de **FASO-SÉCUR** pendant le Sprint Technique Pré-Hackathon 226 sont documentées dans ce fichier.

---

## [1.1.0] — 2026-10-28 (Durcissement Post-Audit de Sécurité)
### Sécurité & Cryptographie
- **Accord de clé Diffie-Hellman `ECDH P-256` (X3DH)** : Ajout de `derivePairwiseECDHWrappingKey` et `buildECDHWrappedGroupSessionBundles` dans `e2eeEngine.js` pour encapsuler individuellement les clés de session Megolm pour chaque membre habilité.
- **Vérification mathématique des signatures `ECDSA P-256` (Client + Serveur)** :
  - Vérification côté client via `window.crypto.subtle.verify` à la réception de chaque enveloppe dans `decryptE2EEMessagePayload`.
  - Vérification côté serveur via `PyCA cryptography` (`ec.SECP256R1`) sur les pré-clés signées (`SignedPreKey`), les enveloppes de messages et les accusés de lecture probants.
- **Architecture Sealed Sender intégrale** : Suppression de `sender_id` et de `created_at` milliseconde dans `encrypted_messages` ; scellement de `classification` et `message_kind` sous `"SEALED_E2EE"` en base de données.
- **Chiffrement au repos du trousseau local (`AES-256-GCM Key Wrapping`)** dans `localStorage`.
- **Protection Anti-Brute-Force (`HTTP 429`)** sur `/api/auth/login` après 5 tentatives échouées.
- **Durcissement opérationnel** : Flag `FASO_SECUR_DEMO_MODE`, restriction `CORS`, `.env.example` et `healthcheck` Docker Compose.

---

## [1.0.0] — 2026-10-28 (Version Initiale du Sprint)
- Serveur souverain Zero-Knowledge FastAPI + WebSockets temps réel.
- Authentification forte 2FA TOTP (RFC 6238) et gestion des rôles RBAC.
- Révocation immédiate en cours de conversation (`REMOTE_WIPE_AND_REVOKE` + rotation `crypto_epoch`).
- Client React multilingue (**Français, Mooré, Dioula, Fulfulde**) avec notes vocales E2EE, niveaux de classification et accusés de lecture à valeur probante.
