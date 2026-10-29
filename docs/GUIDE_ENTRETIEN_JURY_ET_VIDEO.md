# GUIDE D'ENTRETIEN TECHNIQUE (15 MIN) & SCRIPT VIDÉO (3 MIN)
**Préparation aux épreuves éliminatoires du Jury — FASO-SÉCUR (Hackathon 226)**

---

## PARTIE 1 : CHECKLIST OPÉRATIONNELLE DES 5 ÉPREUVES EN DIRECT DU JURY

| Épreuve en direct du Jury | Action à réaliser devant le Jury | Preuve technique immédiate |
| :--- | :--- | :--- |
| **1. « Le serveur ne lit rien »** | Envoyer un message classifié et une note vocale, puis ouvrir l'onglet **« Inspecteur Jury (BDD & Réseau) »** (ou exécuter un `SELECT * FROM encrypted_messages;`). | `plaintext_columns_in_db: 0`, `all_payloads_encrypted: true`, `all_totp_secrets_fernet_encrypted_at_rest: true`. Aucun texte, fichier ni `sender_id` en clair. |
| **2. « Révocation »** | Connecter `BF-DGTD-001` (Fenêtre A) et `BF-MISSION-999` (Fenêtre B) dans le même salon. Cliquer sur **« Révoquer immédiatement »** sur `BF-MISSION-999`. | En moins d'une seconde, la Fenêtre B reçoit `REMOTE_WIPE_AND_REVOKE`, purge ses clés et affiche l'écran rouge de verrouillage ; le salon passe à `Epoch #2` et `BF-MISSION-999` est exclu des nouvelles enveloppes Signal. |
| **3. « Intrus »** | Sur l'écran de connexion, cliquer sur **« Simuler l'attaque d'un Intrus non enrôlé »** ou tenter une connexion avec un matricule inconnu. | Rejet immédiat `HTTP 403 Forbidden` (« INTRUS REJETÉ ») et inscription d'une alerte `CRITICAL` dans `security_audit_logs`. |
| **4. « Explication du code »** | Présenter l'une des 4 fonctions ci-dessous (Partie 3) ligne par ligne dans [`e2eeEngine.js`](../frontend/src/crypto/e2eeEngine.js), [`auth.py`](../backend/auth.py) ou [`main.py`](../backend/main.py). | Maîtrise complète du flux `libsignal` pair-à-pair (`SessionBuilder` X3DH + `SessionCipher` Double Ratchet), des clés aléatoires de pièces jointes, du 2FA TOTP chiffré Fernet et de la révocation. |
| **5. « Questions sur les choix techniques »** | Répondre avec transparence sur l'architecture, les métadonnées résiduelles, la distribution GPL-3.0-only, la permission MIT du code original et les limites connues (`REMOTE_WIPE` hors-ligne, coût $O(N)$ de groupe). | Argumentaire précis dans la Partie 4 ci-dessous. |

---

## PARTIE 2 : SCRIPT CHRONOMÉTRÉ DE LA VIDÉO DE DÉMONSTRATION (3 MINUTES MAX)

> **Rappel du règlement** : *« Trois (03) minutes au maximum : échange chiffré entre deux agents, révocation d'un agent et fonctionnalité innovante principale. »*

1. **0:00 – 0:30 | Ouverture, Connexion Forte 2FA TOTP & Rejet d'un Intrus** :
   - Ouvrez deux fenêtres de navigateur côte à côte sur `http://localhost:5173` (avec `FASO_SECUR_DEMO_MODE=true`).
   - Cliquez sur **« Simuler l'attaque d'un Intrus non enrôlé »** pour montrer le rejet `403 Forbidden`.
   - **Fenêtre Gauche** : Connectez `BF-DGTD-001` (Aminata OUÉDRAOGO — Administratrice DGTD) avec son code **2FA TOTP (RFC 6238)** calculé localement.
   - **Fenêtre Droite** : Connectez `BF-MISSION-999` (Adama ZONGO — Agent en mission).
2. **0:30 – 1:25 | Échange Chiffré E2EE (Protocole Signal Pair-à-Pair) & Preuve « Le Serveur Ne Lit Rien »** :
   - Dans la Fenêtre Gauche (`BF-DGTD-001`), sélectionnez le niveau **`CONFIDENTIEL`**, cochez **« Exiger un accusé de lecture signé à valeur probante »**, et envoyez une instruction officielle.
   - Dans la Fenêtre Droite (`BF-MISSION-999`), montrez que le message arrive flouté (protection anti-regard), survolez-le pour le déchiffrer via `SessionCipher`, et cliquez sur **« Signer l'accusé de réception officiel (Valeur Probante) »** (signature `ECDSA P-256`).
   - Ouvrez l'onglet **« Inspecteur Jury (BDD & Réseau) »** pour montrer que dans `encrypted_messages`, seul le `ciphertext_payload` (`SIGNAL_X3DH_DOUBLERATCHET_AES256GCM_ECDSA`) et le pseudonyme `pseudo_...` apparaissent : **0 colonne en clair**.
3. **1:25 – 2:15 | Révocation Immédiate en Direct pendant la Conversation** :
   - Dans la Fenêtre Gauche (`BF-DGTD-001`), cliquez sur **« Révoquer un membre en direct »** puis sur **« Révoquer immédiatement »** en face de `BF-MISSION-999`.
   - Montrez qu'**instantanément**, la Fenêtre Droite (`BF-MISSION-999`) bascule sur l'écran rouge **« ACCÈS RÉVOQUÉ IMMÉDIATEMENT & TROUSSEAU E2EE PURGÉ »** et que dans la Fenêtre Gauche, le canal passe à **`Epoch #2`**. Envoyez un nouveau message dans la Fenêtre Gauche pour prouver que `BF-MISSION-999` est exclu des enveloppes Signal.
4. **2:15 – 3:00 | Fonctionnalités Innovantes (Langues Nationales + Note Vocale E2EE)** :
   - Basculez la langue de l'interface en **Mooré**, **Dioula**, puis **Fulfulde** dans l'en-tête.
   - Enregistrez et envoyez une **note vocale chiffrée de bout en bout en Mooré** (bourrée à 4 096 octets avec une clé aléatoire `AES-256-GCM` distribuée via Signal), puis cliquez sur **« Déchiffrer localement »** pour l'écouter.

---

## PARTIE 3 : EXPLICATION DU CODE POUR L'ORAL ÉLIMINATOIRE (4 FONCTIONS CLÉS)

### 1. Chiffrement Signal Pair-à-Pair des Messages et Pièces Jointes : `encryptE2EEMessagePayload` & `encryptBinaryAttachmentE2EE` dans [`frontend/src/crypto/e2eeEngine.js`](../frontend/src/crypto/e2eeEngine.js)
- **Ce qu'elles font** : Chiffrent chaque message de salon (1-à-1 ou groupe) via les sessions **Signal X3DH + Double Ratchet** (`@privacyresearch/libsignal-protocol-typescript`) de chaque membre actif autorisé, sans aucun repli vers un protocole maison.
- **Explication étape par étape** :
  1. `initializeAgentKeystore` génère via `KeyHelper` l'identité `Curve25519`, la `SignedPreKey` `Ed25519` et **20 `One-Time PreKeys`**, et persiste l'état complet du `SignalProtocolStore` chiffré au repos par une `CryptoKey` `AES-256-GCM` **non-extractible (`extractable: false`)** dans `IndexedDB`.
  2. `encryptE2EEMessagePayload` bourre le message JSON par blocs de **256 octets**, puis pour chaque membre actif non révoqué : ouvre une session X3DH si nécessaire (`new SessionBuilder(localStore, address).processPreKey(deviceBundle)`, consommant une `One-Time PreKey`) et chiffre le message avec `new SessionCipher(localStore, address).encrypt(paddedBytes)` (`PreKeyWhisperMessage` type 3 puis `WhisperMessage` type 1). L'enveloppe multi-destinataires est ensuite signée en `ECDSA P-256`.
  3. Pour une pièce jointe, `encryptBinaryAttachmentE2EE` génère une clé symétrique aléatoire fraîche de 256 bits (`AES-256-GCM`, bourrage à **4 096 octets**). Le blob chiffré est envoyé sur `/api/blobs` sans la clé, et la clé `attachmentKeyB64` est distribuée à l'intérieur des enveloppes Signal pair-à-pair.

### 2. Vérification du 2FA TOTP & Chiffrement Fernet au repos : `verify_totp_code` dans [`backend/auth.py`](../backend/auth.py)
- **Explication étape par étape** :
  1. Appelle `decrypt_totp_secret_at_rest` (`cryptography.fernet.Fernet`) dont la clé maîtresse est stockée hors du dossier de la base de données (`.faso_secur_secrets` / `/app/secrets` ou Docker Secret `FASO_SECUR_TOTP_FERNET_KEY_FILE`).
  2. Décode le secret Base32 et vérifie le code à 6 chiffres via la classe officielle `TOTP` de **`PyCA cryptography`** (RFC 6238, fenêtre de 30 s, tolérance `±1` palier).

### 3. Contrôle d'accès, Anti-Downgrade et Révocation : `verify_and_load_active_agent` ([`backend/auth.py`](../backend/auth.py)) & `post_encrypted_message` ([`backend/main.py`](../backend/main.py))
- **Explication étape par étape** :
  1. Vérifie le JWT (`PyJWT`), l'enrôlement préalable et `agent.token_version == payload["token_version"]`.
  2. Dans `post_encrypted_message`, vérifie que `req.e2ee_protocol == "SIGNAL_X3DH_DOUBLERATCHET_AES256GCM_ECDSA"` (rejetant `HTTP 400` tout ancien protocole ou protocole inconnu) et vérifie la signature `ECDSA P-256` contre `current_agent.e2ee_signing_public_key`.

### 4. Révocation atomique et rotation d'époque : `revoke_agent_immediately` dans [`backend/main.py`](../backend/main.py)
- **Explication étape par étape** :
  1. Passe `target.is_revoked = True`, incrémente `target.token_version += 1`, efface ses clés publiques de l'annuaire et retire ses enveloppes des salons.
  2. Supprime l'agent de `ChannelMember` et incrémente `channel.crypto_epoch += 1` sur chaque salon concerné.
  3. Envoie `REMOTE_WIPE_AND_REVOKE` sur les WebSockets de l'agent révoqué (`code 4003`) et diffuse `GROUP_CRYPTO_EPOCH_ROTATED` aux membres restants afin que les messages suivants soient chiffrés via Signal uniquement pour les membres restants.

---

## PARTIE 4 : RÉPONSES AUX QUESTIONS PIÈGES DU JURY

- **« Pourquoi chiffrer chaque message de groupe via des sessions Signal pair-à-pair plutôt qu'une clé de groupe WebCrypto ? »**
  - *Réponse* : `@privacyresearch/libsignal-protocol-typescript` fournit `SessionBuilder` (X3DH) et `SessionCipher` (Double Ratchet) mais pas de primitive *Sender Keys*. Utiliser des sessions Signal pair-à-pair garantit que chaque message et chaque clé de pièce jointe bénéficie réellement des propriétés X3DH + Double Ratchet du protocole Signal autorisé, sans aucun assemblage cryptographique maison.
- **« Que se passe-t-il si l'appareil de l'agent révoqué est hors-ligne au moment de la révocation ? »**
  - *Réponse* : Côté serveur et cryptographiquement, l'exclusion est immédiate (`token_version` incrémenté, retrait du salon, `crypto_epoch + 1` excluant l'agent des nouvelles enveloppes Signal). L'effacement physique du stockage local (`REMOTE_WIPE`) sur son appareil s'exécutera dès que le terminal tentera de se reconnecter au serveur.
