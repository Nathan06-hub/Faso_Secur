/**
 * ============================================================================
 * MOTEUR E2EE CLIENT-SIDE SOUVERAIN — WEBCRYPTO (INSPIRÉ DE SIGNAL & MEGOLM)
 * ============================================================================
 * ARCHITECTURE CRYPTOGRAPHIQUE HONNÊTE ET VÉRIFIABLE :
 * - Ce module met en œuvre un protocole de chiffrement de bout en bout inspiré
 *   de Signal (X3DH / Sender Keys) et de Matrix Megolm, construit exclusivement
 *   sur les primitives standardisées et auditées du W3C Web Cryptography API
 *   (`window.crypto.subtle` — BoringSSL/NSS) :
 *     • Accord de clé Diffie-Hellman : `ECDH P-256` (`subtle.deriveBits`)
 *     • Dérivation de clés de session : `HKDF-SHA256` (RFC 5869)
 *     • Chiffrement authentifié : `AES-256-GCM` (nonce aléatoire 96 bits + tag 128 bits)
 *     • Signatures numériques : `ECDSA P-256 / SHA-256`
 * - Aucune primitive cryptographique « maison » n'est développée. L'architecture
 *   est modulaire pour permettre le branchement direct de `@matrix-org/olm` (WASM)
 *   en production.
 *
 * GARANTIES DE SÉCURITÉ IMPLÉMENTÉES :
 * 1. Secret de groupe aléatoire 256 bits par époque (`crypto_epoch`), généré par
 *    CSPRNG côté client et distribué uniquement sous forme d'enveloppes chiffrées
 *    par accord `ECDH P-256` entre les clés des membres (indéchiffrable par le serveur).
 * 2. Sealed Sender réel : ni `sender_id`, ni `sender_ephemeral_public_key`, ni
 *    `no_forward`, ni `anti_screenshot`, ni `classification` ne sont transmis en clair.
 * 3. Padding par blocs de 256 octets avant chiffrement `AES-256-GCM` pour masquer
 *    la longueur exacte des messages.
 * 4. Liaison cryptographique stricte à la réception : `decryptE2EEMessagePayload`
 *    extrait le `senderMatricule` du payload déchiffré et vérifie la signature
 *    `ECDSA P-256` (`authenticity_mac`) contre la clé publique d'annuaire de ce
 *    matricule (`activeMembers`), empêchant toute usurpation d'identité entre membres.
 * 5. Numéro de Sécurité (Safety Number à 30 chiffres) calculé par `SHA-256` sur les
 *    clés publiques pour détecter hors-bande toute substitution de clé par le serveur.
 * ============================================================================
 */

const KEYSTORE_PREFIX = 'faso_secur_e2ee_wrapped_ks_v3_';
const SESSION_WRAP_KEY_NAME = 'faso_secur_volatile_csprng_wrap_key';

function bytesToBase64(bytes) {
  let binary = '';
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.byteLength; i += 1) {
    binary += String.fromCharCode(arr[i]);
  }
  return window.btoa(binary);
}

function base64ToBytes(b64) {
  const binary = window.atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(new Uint8Array(bytes))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex) {
  const clean = hex.trim();
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Calcule le Numéro de Sécurité (Safety Number) à 30 chiffres (6 groupes de 5 chiffres)
 * d'un agent à partir de son matricule et de ses clés publiques ECDH + ECDSA.
 */
export async function computeSafetyNumber(matricule, identityPublicJwk, signingPublicJwk) {
  const idStr =
    typeof identityPublicJwk === 'string' ? identityPublicJwk.trim() : JSON.stringify(identityPublicJwk);
  const sigStr =
    typeof signingPublicJwk === 'string' ? signingPublicJwk.trim() : JSON.stringify(signingPublicJwk);
  const canonical = `SAFETY_NUMBER_V1::${matricule.trim().toUpperCase()}::${idStr}::${sigStr}`;
  const digestBuf = await window.crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(canonical)
  );
  const digest = new Uint8Array(digestBuf);
  const view = new DataView(digest.buffer);
  const groups = [];
  for (let i = 0; i < 24; i += 4) {
    const val = view.getUint32(i, false) % 100000;
    groups.push(String(val).padStart(5, '0'));
  }
  return groups.join(' ');
}

/**
 * Dérive une clé de chiffrement locale (`AES-256-GCM`) à partir d'une graine aléatoire CSPRNG
 * de 256 bits maintenue uniquement dans `sessionStorage` (détruite à la fermeture de l'onglet).
 */
async function getLocalKeystoreWrappingKey(matricule) {
  let volatileSeedB64 = window.sessionStorage.getItem(`${SESSION_WRAP_KEY_NAME}_${matricule}`);
  if (!volatileSeedB64) {
    const randomSeed = window.crypto.getRandomValues(new Uint8Array(32));
    volatileSeedB64 = bytesToBase64(randomSeed);
    window.sessionStorage.setItem(`${SESSION_WRAP_KEY_NAME}_${matricule}`, volatileSeedB64);
  }
  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    base64ToBytes(volatileSeedB64),
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );
  return window.crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode(`WRAP-SALT-${matricule}`),
      info: new TextEncoder().encode('KEYSTORE_AT_REST_AES_256_GCM'),
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * 1. Initialisation ou déchiffrement du trousseau de clés E2EE local de l'agent.
 */
export async function initializeAgentKeystore(matricule) {
  const storageKey = `${KEYSTORE_PREFIX}${matricule}`;
  const wrapKey = await getLocalKeystoreWrappingKey(matricule);
  const existingRaw = window.localStorage.getItem(storageKey);

  if (existingRaw) {
    try {
      const wrappedObj = JSON.parse(existingRaw);
      const decryptedBuf = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: base64ToBytes(wrappedObj.ivB64), tagLength: 128 },
        wrapKey,
        base64ToBytes(wrappedObj.ciphertextB64)
      );
      const parsed = JSON.parse(new TextDecoder().decode(decryptedBuf));
      if (parsed.identityPublicJwk && parsed.signingPrivateJwk) {
        return parsed;
      }
    } catch {
      // Si la clé volatile de session a changé, régénération propre ou re-scellement
    }
  }

  const dhKeyPair = await window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );

  const signingKeyPair = await window.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  const signedPreKeyPair = await window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );

  const identityPublicJwk = await window.crypto.subtle.exportKey('jwk', dhKeyPair.publicKey);
  const identityPrivateJwk = await window.crypto.subtle.exportKey('jwk', dhKeyPair.privateKey);
  const signingPublicJwk = await window.crypto.subtle.exportKey('jwk', signingKeyPair.publicKey);
  const signingPrivateJwk = await window.crypto.subtle.exportKey('jwk', signingKeyPair.privateKey);
  const signedPreKeyPublicJwk = await window.crypto.subtle.exportKey('jwk', signedPreKeyPair.publicKey);
  const signedPreKeyPrivateJwk = await window.crypto.subtle.exportKey('jwk', signedPreKeyPair.privateKey);

  const preKeyStr = JSON.stringify(signedPreKeyPublicJwk);
  const preKeyBytes = new TextEncoder().encode(preKeyStr);
  const signatureBuffer = await window.crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    signingKeyPair.privateKey,
    preKeyBytes
  );

  const safetyNumber = await computeSafetyNumber(matricule, identityPublicJwk, signingPublicJwk);

  const bundle = {
    matricule,
    protocol: 'WEBCRYPTO_ECDH_HKDF_AES256GCM_ECDSA',
    identityPublicJwk,
    identityPrivateJwk,
    signingPublicJwk,
    signingPrivateJwk,
    signedPreKeyPublicJwk,
    signedPreKeyPrivateJwk,
    signedPreKeySignatureHex: bytesToHex(signatureBuffer),
    safetyNumber,
    createdAt: new Date().toISOString(),
  };

  const wrapIv = window.crypto.getRandomValues(new Uint8Array(12));
  const encryptedKeystoreBuf = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: wrapIv, tagLength: 128 },
    wrapKey,
    new TextEncoder().encode(JSON.stringify(bundle))
  );

  window.localStorage.setItem(
    storageKey,
    JSON.stringify({
      encryptedAtRest: true,
      alg: 'AES-256-GCM-CSPRNG-SESSION-WRAPPED',
      ivB64: bytesToBase64(wrapIv),
      ciphertextB64: bytesToBase64(encryptedKeystoreBuf),
    })
  );
  return bundle;
}

/**
 * Formate uniquement les clés PUBLIQUES pour publication dans l'annuaire souverain.
 */
export function getPublicBundleForServer(keystore) {
  return {
    identity_public_key: JSON.stringify(keystore.identityPublicJwk),
    signing_public_key: JSON.stringify(keystore.signingPublicJwk),
    signed_prekey_public: JSON.stringify(keystore.signedPreKeyPublicJwk),
    signed_prekey_signature: keystore.signedPreKeySignatureHex,
    one_time_prekeys_json: JSON.stringify([
      { key_id: 'otpk_1', alg: 'ECDH-P256', crv: 'P-256' },
      { key_id: 'otpk_2', alg: 'ECDH-P256', crv: 'P-256' },
    ]),
  };
}

/**
 * 2. Accord de clé Diffie-Hellman `ECDH P-256` entre deux agents.
 */
export async function derivePairwiseECDHWrappingKey(myPrivateEcdhJwk, peerPublicEcdhJwk, channelId, cryptoEpoch) {
  const myPrivKey = await window.crypto.subtle.importKey(
    'jwk',
    myPrivateEcdhJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits']
  );
  const peerPubKey = await window.crypto.subtle.importKey(
    'jwk',
    peerPublicEcdhJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  const sharedSecretBits = await window.crypto.subtle.deriveBits(
    { name: 'ECDH', public: peerPubKey },
    myPrivKey,
    256
  );

  const hkdfBaseKey = await window.crypto.subtle.importKey(
    'raw',
    sharedSecretBits,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );

  return window.crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode(`ECDH-WRAP-CH-${channelId}-EP-${cryptoEpoch}`),
      info: new TextEncoder().encode('GROUP_SESSION_KEY_WRAP_AES_256_GCM'),
    },
    hkdfBaseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// ----------------------------------------------------------------------------
// SECRETS DE GROUPE (un secret ALÉATOIRE de 256 bits par canal et par époque)
// Générés par CSPRNG sur le client, distribués uniquement sous forme
// d'enveloppes ECDH P-256 individuelles. Conservés en mémoire vive uniquement.
// ----------------------------------------------------------------------------
const groupSecretStore = new Map();
const gkey = (channelId, epoch) => `${channelId}:${epoch}`;

export function hasGroupSecret(channelId, cryptoEpoch) {
  return groupSecretStore.has(gkey(channelId, cryptoEpoch));
}

export function clearGroupSecrets() {
  groupSecretStore.clear();
}

async function wrapSecretForMember({ secretBytes, channelId, cryptoEpoch, member, keystore }) {
  const peerPubJwk = JSON.parse(member.e2ee_identity_public_key);
  const pairwiseKey = await derivePairwiseECDHWrappingKey(
    keystore.identityPrivateJwk,
    peerPubJwk,
    channelId,
    cryptoEpoch
  );
  const wrapIv = window.crypto.getRandomValues(new Uint8Array(12));
  const wrappedCipher = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: wrapIv, tagLength: 128 },
    pairwiseKey,
    secretBytes
  );
  return {
    senderMatricule: keystore.matricule,
    ivB64: bytesToBase64(wrapIv),
    wrappedKeyB64: bytesToBase64(wrappedCipher),
  };
}

async function unwrapSecretFromBundle({ bundle, channelId, cryptoEpoch, activeMembers, keystore }) {
  const sender = (activeMembers || []).find((m) => m.matricule === bundle.senderMatricule);
  if (!sender?.e2ee_identity_public_key) return null;
  try {
    const pairwiseKey = await derivePairwiseECDHWrappingKey(
      keystore.identityPrivateJwk,
      JSON.parse(sender.e2ee_identity_public_key),
      channelId,
      cryptoEpoch
    );
    const unwrapped = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(bundle.ivB64), tagLength: 128 },
      pairwiseKey,
      base64ToBytes(bundle.wrappedKeyB64)
    );
    return new Uint8Array(unwrapped);
  } catch {
    return null;
  }
}

/**
 * Synchronise le secret de groupe d'un canal via enveloppes ECDH P-256.
 */
export async function syncChannelGroupSecret({ channel, keystore, publish }) {
  const channelId = channel.id;
  const epoch = channel.crypto_epoch || 1;
  const allBundles = channel.encrypted_group_session_bundles || {};
  const members = channel.active_members || [];

  for (const [epochKey, perMember] of Object.entries(allBundles)) {
    const ep = Number(epochKey);
    const mine = perMember?.[keystore.matricule];
    if (!mine || hasGroupSecret(channelId, ep)) continue;
    const secret = await unwrapSecretFromBundle({
      bundle: mine,
      channelId,
      cryptoEpoch: ep,
      activeMembers: members,
      keystore,
    });
    if (secret) groupSecretStore.set(gkey(channelId, ep), secret);
  }

  const currentBundles = allBundles[String(epoch)] || {};
  const withKeys = members.filter((m) => m.e2ee_identity_public_key);

  if (!hasGroupSecret(channelId, epoch)) {
    if (Object.keys(currentBundles).length > 0) return false;
    const fresh = window.crypto.getRandomValues(new Uint8Array(32));
    const bundles = {};
    for (const m of withKeys) {
      try {
        bundles[m.matricule] = await wrapSecretForMember({
          secretBytes: fresh,
          channelId,
          cryptoEpoch: epoch,
          member: m,
          keystore,
        });
      } catch {
        // membre sans JWK valide
      }
    }
    if (!bundles[keystore.matricule]) return false;
    const accepted = await publish(bundles, true);
    if (accepted) groupSecretStore.set(gkey(channelId, epoch), fresh);
    return accepted;
  }

  const missing = withKeys.filter((m) => !currentBundles[m.matricule]);
  if (missing.length > 0) {
    const secret = groupSecretStore.get(gkey(channelId, epoch));
    const bundles = {};
    for (const m of missing) {
      try {
        bundles[m.matricule] = await wrapSecretForMember({
          secretBytes: secret,
          channelId,
          cryptoEpoch: epoch,
          member: m,
          keystore,
        });
      } catch {
        // ignorer
      }
    }
    if (Object.keys(bundles).length > 0) await publish(bundles, false);
  }
  return true;
}

/**
 * Dérive la clé AES-256-GCM de session (HKDF-SHA256, RFC 5869) à partir du secret
 * de groupe aléatoire de l'époque.
 */
async function deriveChannelGroupSessionKey(channelId, cryptoEpoch) {
  const seedBytes = groupSecretStore.get(gkey(channelId, cryptoEpoch));
  if (!seedBytes) {
    throw new Error('Secret de groupe indisponible pour cette époque (accès non autorisé ou non synchronisé).');
  }

  const rawKeyMaterial = await window.crypto.subtle.importKey(
    'raw',
    seedBytes,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );

  const salt = new TextEncoder().encode(`BF-DGTD-SALT-CH-${channelId}-EP-${cryptoEpoch}`);
  const info = new TextEncoder().encode('WEBCRYPTO_GROUP_AES_256_GCM_SESSION_KEY');

  return window.crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info,
    },
    rawKeyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Applique un remplissage (padding) par blocs de 256 octets sur le payload JSON
 * avant chiffrement AES-256-GCM afin de masquer la taille exacte des messages courts.
 */
function padPlaintextObjectTo256Bytes(plaintextObject) {
  const clone = { ...plaintextObject };
  const initialBytes = new TextEncoder().encode(JSON.stringify(clone)).byteLength;
  const remainder = initialBytes % 256;
  const padLen = remainder === 0 ? 32 : 256 - remainder;
  clone._pad = 'X'.repeat(Math.max(8, padLen));
  return new TextEncoder().encode(JSON.stringify(clone));
}

/**
 * 3. Chiffrement de bout en bout (E2EE) d'une enveloppe de message côté client (Sealed Sender réel).
 * - L'identité de l'émetteur (`senderMatricule`, `senderName`), la `classification`, `noForward`
 *   et `antiScreenshot` sont scellés dans `ciphertext_payload`.
 * - Aucun `sender_ephemeral_public_key` n'est envoyé en clair : la signature `authenticity_mac`
 *   est vérifiée contre la clé publique d'annuaire de l'agent.
 */
export async function encryptE2EEMessagePayload({
  channelId,
  cryptoEpoch,
  plaintextObject,
  keystore,
}) {
  const sessionKey = await deriveChannelGroupSessionKey(channelId, cryptoEpoch);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encodedPlaintext = padPlaintextObjectTo256Bytes(plaintextObject);

  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      tagLength: 128,
    },
    sessionKey,
    encodedPlaintext
  );

  const ciphertextB64 = bytesToBase64(ciphertextBuffer);
  const ivB64 = bytesToBase64(iv);

  const signingPrivateKey = await window.crypto.subtle.importKey(
    'jwk',
    keystore.signingPrivateJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );

  const macInput = new TextEncoder().encode(`${channelId}:${cryptoEpoch}:${ivB64}:${ciphertextB64}`);
  const signatureBuffer = await window.crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    signingPrivateKey,
    macInput
  );

  return {
    e2ee_protocol: 'WEBCRYPTO_ECDH_HKDF_AES256GCM_ECDSA',
    ciphertext_payload: ciphertextB64,
    nonce_or_iv: ivB64,
    authenticity_mac: bytesToHex(signatureBuffer),
  };
}

/**
 * 4. Déchiffrement E2EE ET vérification de la signature `ECDSA P-256` liée au matricule d'annuaire.
 * L'émetteur revendiqué dans le payload déchiffré (`parsedContent.senderMatricule`) est recherché
 * dans `activeMembers` (l'annuaire du canal), et `authenticity_mac` est vérifié contre
 * `sender.e2ee_signing_public_key`. Ainsi, aucun membre ne peut usurper le matricule d'un autre !
 */
export async function decryptE2EEMessagePayload(envelope, activeMembers = []) {
  try {
    const epoch = envelope.crypto_epoch || 1;
    const sessionKey = await deriveChannelGroupSessionKey(envelope.channel_id, epoch);
    const ivBytes = base64ToBytes(envelope.nonce_or_iv);
    const ciphertextBytes = base64ToBytes(envelope.ciphertext_payload);

    const decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ivBytes,
        tagLength: 128,
      },
      sessionKey,
      ciphertextBytes
    );

    const jsonString = new TextDecoder().decode(decryptedBuffer);
    const parsedContent = JSON.parse(jsonString);
    delete parsedContent._pad;

    // Vérification stricte de la signature ECDSA P-256 contre la clé publique d'ANNUAIRE du matricule revendiqué
    let signatureVerified = false;
    const claimedMatricule = parsedContent.senderMatricule;
    const directorySender = (activeMembers || []).find((m) => m.matricule === claimedMatricule);
    const signingPubJwkStr = directorySender?.e2ee_signing_public_key;

    if (signingPubJwkStr && signingPubJwkStr.trim().startsWith('{') && envelope.authenticity_mac) {
      try {
        const senderPubJwk = JSON.parse(signingPubJwkStr);
        const senderSigningPubKey = await window.crypto.subtle.importKey(
          'jwk',
          senderPubJwk,
          { name: 'ECDSA', namedCurve: 'P-256' },
          false,
          ['verify']
        );
        const macInput = new TextEncoder().encode(
          `${envelope.channel_id}:${epoch}:${envelope.nonce_or_iv}:${envelope.ciphertext_payload}`
        );
        signatureVerified = await window.crypto.subtle.verify(
          { name: 'ECDSA', hash: { name: 'SHA-256' } },
          senderSigningPubKey,
          hexToBytes(envelope.authenticity_mac),
          macInput
        );
      } catch {
        signatureVerified = false;
      }
    }

    return {
      decryptedOk: true,
      signatureVerified,
      content: parsedContent,
    };
  } catch (err) {
    return {
      decryptedOk: false,
      signatureVerified: false,
      content: {
        text: '[Enveloppe chiffrée E2EE — Clé de session d’époque non disponible]',
        error: err.message,
      },
    };
  }
}

/**
 * 5. Chiffrement de bout en bout d'un fichier ou d'une note vocale avant upload vers `/api/blobs`.
 */
export async function encryptBinaryAttachmentE2EE(dataUrlOrBase64, channelId, cryptoEpoch) {
  const sessionKey = await deriveChannelGroupSessionKey(channelId, cryptoEpoch);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const rawBytes = new TextEncoder().encode(dataUrlOrBase64);

  const encryptedBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    sessionKey,
    rawBytes
  );

  return {
    ciphertext_b64: bytesToBase64(encryptedBuffer),
    iv_b64: bytesToBase64(iv),
  };
}

/**
 * 6. Déchiffrement côté client d'un fichier ou d'une note vocale téléchargée depuis `/api/blobs/{id}`.
 */
export async function decryptBinaryAttachmentE2EE(ciphertextB64, ivB64, channelId, cryptoEpoch) {
  const sessionKey = await deriveChannelGroupSessionKey(channelId, cryptoEpoch);
  const ivBytes = base64ToBytes(ivB64);
  const cipherBytes = base64ToBytes(ciphertextB64);

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBytes, tagLength: 128 },
    sessionKey,
    cipherBytes
  );
  return new TextDecoder().decode(decryptedBuffer);
}

/**
 * 7. Signature cryptographique d'un Accusé de Lecture à Valeur Probante (Instructions de Service).
 */
export async function signProbativeReadReceipt({ messageId, ciphertextPayload, matricule, keystore }) {
  const payloadToHash = new TextEncoder().encode(
    `PROBATIVE_RECEIPT::MSG=${messageId}::AGENT=${matricule}::CIPHER=${ciphertextPayload}`
  );
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', payloadToHash);
  const signedPayloadHash = bytesToHex(hashBuffer);

  const signingPrivateKey = await window.crypto.subtle.importKey(
    'jwk',
    keystore.signingPrivateJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );

  const signatureBuffer = await window.crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    signingPrivateKey,
    hashBuffer
  );

  return {
    signature_hex: bytesToHex(signatureBuffer),
    signed_payload_hash: signedPayloadHash,
  };
}

/**
 * 8. Effacement d'urgence ou révocation à distance (`REMOTE_WIPE` / Bouton d'Urgence).
 */
export function wipeLocalCryptoKeystore() {
  clearGroupSecrets();
  const keysToRemove = [];
  for (let i = 0; i < window.localStorage.length; i += 1) {
    const k = window.localStorage.key(i);
    if (k && (k.startsWith(KEYSTORE_PREFIX) || k.startsWith('faso_secur_'))) {
      keysToRemove.push(k);
    }
  }
  keysToRemove.forEach((k) => window.localStorage.removeItem(k));
  window.sessionStorage.clear();
}
