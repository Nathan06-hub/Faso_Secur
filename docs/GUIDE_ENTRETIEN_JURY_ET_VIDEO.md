# GUIDE D'ENTRETIEN TECHNIQUE (15 MIN) & SCRIPT VIDÉO (3 MIN)
**Préparation aux épreuves éliminatoires du Jury — FASO-SÉCUR (Hackathon 226)**

---

## PARTIE 1 : SCRIPT CHRONOMÉTRÉ DE LA VIDÉO DE DÉMONSTRATION (3 MINUTES MAX)

> **Rappel du règlement** : *« Trois (03) minutes au maximum : échange chiffré entre deux agents, révocation d'un agent et fonctionnalité innovante principale. »*

1. **0:00 – 0:30 | Ouverture & Connexion Forte 2FA TOTP de 2 Agents** :
   - Ouvrez deux fenêtres de navigateur côte à côte sur `http://localhost:5173`.
   - **Fenêtre Gauche** : Cliquez sur le compte fictif `BF-DGTD-001` (Aminata OUÉDRAOGO — Administratrice DGTD) et connectez-vous avec le code **2FA TOTP (RFC 6238)**.
   - **Fenêtre Droite** : Cliquez sur `BF-MISSION-999` (Adama ZONGO — Agent en mission) et connectez-vous.
   - Cliquez également 2 secondes sur le bouton **« Simuler l'attaque d'un Intrus non enrôlé »** sur l'écran de connexion pour montrer le rejet `403 Forbidden`.
2. **0:30 – 1:25 | Échange Chiffré E2EE & Preuve « Le Serveur Ne Lit Rien »** :
   - Dans la Fenêtre Gauche (`BF-DGTD-001`), sélectionnez le niveau **`CONFIDENTIEL`**, cochez **« Exiger un accusé de lecture signé à valeur probante »**, et envoyez une instruction officielle.
   - Dans la Fenêtre Droite (`BF-MISSION-999`), montrez que le message arrive flouté (protection anti-regard), survolez-le pour le lire, et cliquez sur **« Signer l'accusé de réception officiel (Valeur Probante) »** (signature `ECDSA-SHA256`).
   - Cliquez sur l'onglet **« Inspecteur Jury (BDD & Réseau) »** pour montrer que dans la table SQL `encrypted_messages`, seul le `ciphertext_payload` (`AES-256-GCM`) et le pseudonyme `pseudo_...` apparaissent : **0 colonne en clair**.
3. **1:25 – 2:15 | Révocation Immédiate en Direct pendant la Conversation** :
   - Dans la Fenêtre Gauche (`BF-DGTD-001`), cliquez sur **« Révoquer un membre en direct »** puis sur **« Révoquer immédiatement »** en face de `BF-MISSION-999` (Adama ZONGO).
   - Montrez qu'**instantanément**, la Fenêtre Droite (`BF-MISSION-999`) bascule sur l'écran rouge **« ACCÈS RÉVOQUÉ IMMÉDIATEMENT & TROUSSEAU E2EE PURGÉ »** (WebSocket coupé + clés locales effacées) et que dans la Fenêtre Gauche, le canal est passé à **`Epoch #2`** (rotation des clés de groupe).
4. **2:15 – 3:00 | Fonctionnalités Innovantes (Langues Nationales + Note Vocale E2EE)** :
   - Basculez la langue de l'interface en **Mooré**, **Dioula**, puis **Fulfulde** dans l'en-tête.
   - Enregistrez et envoyez une **note vocale chiffrée de bout en bout en Mooré**, puis cliquez sur **« Déchiffrer localement »** pour la lire.

---

## PARTIE 2 : EXPLICATION DU CODE POUR L'ORAL ÉLIMINATOIRE (QUESTIONS DU JURY)

> **Règle éliminatoire** : *« Le jury désigne une fonction liée au chiffrement ou à l'authentification, qu'un membre désigné par le jury doit expliquer. L'incapacité à expliquer le code ou les mécanismes de sécurité présentés entraîne la disqualification de l'équipe. »*

Voici les **4 fonctions clés** que chaque membre de l'équipe doit connaître parfaitement :

### 1. Chiffrement E2EE côté client : `encryptE2EEMessagePayload` dans [`frontend/src/crypto/e2eeEngine.js`](../frontend/src/crypto/e2eeEngine.js)
- **Ce qu'elle fait** : Chiffre le message côté navigateur avant tout appel réseau vers FastAPI.
- **Comment l'expliquer au jury** :
  1. Elle appelle `deriveChannelMegolmSessionKey(channelId, cryptoEpoch)` qui utilise le standard **`HKDF-SHA256` (RFC 5869)** via `window.crypto.subtle.deriveKey` pour dériver une clé symétrique **`AES-256-GCM`** de 256 bits propre au canal et à son époque de révocation (`cryptoEpoch`).
  2. Elle génère un vecteur d'initialisation aléatoire cryptographique de 96 bits (`12 octets`) via `window.crypto.getRandomValues(new Uint8Array(12))`.
  3. Elle chiffre l'objet JSON du message avec `window.crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, ...)`, ce qui produit le texte chiffré + un tag d'intégrité GCM de 128 bits.
  4. Elle signe l'enveloppe chiffrée avec la clé privée **`ECDSA P-256`** de l'agent émetteur (`window.crypto.subtle.sign`) pour garantir l'authenticité de l'émetteur.

### 2. Vérification du Second Facteur 2FA : `verify_totp_code` dans [`backend/auth.py`](../backend/auth.py)
- **Ce qu'elle fait** : Vérifie le code à 6 chiffres du second facteur d'authentification selon le standard **RFC 6238 (TOTP)**.
- **Comment l'expliquer au jury** :
  1. Elle décode le secret Base32 de l'agent enrôlé et instancie la classe officielle `TOTP` de la bibliothèque open source **`PyCA cryptography`** (`cryptography.hazmat.primitives.twofactor.totp.TOTP`) avec un pas de temps de 30 secondes (`time_step=30`) et l'algorithme `SHA1` standard RFC 6238.
  2. Elle appelle `totp.verify(code_bytes, now + offset * 30)` avec une tolérance d'horloge de `±1` palier (30 s) pour valider le second facteur sans aucune cryptographie maison.

### 3. Contrôle d'accès et de révocation sur chaque requête : `verify_and_load_active_agent` dans [`backend/auth.py`](../backend/auth.py)
- **Ce qu'elle fait** : Vérifie le jeton JWT sur chaque appel API et chaque connexion WebSocket.
- **Comment l'expliquer au jury** :
  1. Elle décode et vérifie la signature HMAC-SHA256 du JWT via `PyJWT`.
  2. Elle charge l'agent en base (`EnrolledAgent`). Si l'agent n'est pas enrôlé -> rejet `403 Intrus`.
  3. Si `agent.is_revoked == True` ou si `agent.token_version != payload["token_version"]` -> rejet immédiat `403 ACCÈS RÉVOQUÉ`. Ainsi, un jeton JWT même non expiré devient inutilisable à la milliseconde où l'agent est révoqué.

### 4. Révocation atomique et rotation des clés de groupe : `revoke_agent_immediately` dans [`backend/main.py`](../backend/main.py)
- **Ce qu'elle fait** : Coupe immédiatement l'accès d'un agent pendant une conversation de groupe.
- **Comment l'expliquer au jury** :
  1. Passe `target.is_revoked = True`, incrémente `target.token_version += 1` et efface ses clés publiques E2EE de l'annuaire.
  2. Supprime l'agent de la table `ChannelMember` pour tous les groupes et incrémente `channel.crypto_epoch += 1` sur chaque salon concerné.
  3. Appelle `ws_manager.revoke_and_wipe_agent_immediately(...)` qui envoie le signal WebSocket `REMOTE_WIPE_AND_REVOKE` (effaçant les clés privées locales du navigateur de l'agent révoqué), ferme sa connexion WebSocket (`code 4003`), et notifie les membres restants (`GROUP_CRYPTO_EPOCH_ROTATED`) pour qu'ils basculent immédiatement sur la nouvelle clé d'époque.
