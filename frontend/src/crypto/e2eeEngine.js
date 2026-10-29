/**
 * ============================================================================
 * FASO-SÉCUR — Moteur de Chiffrement de Bout en Bout (E2EE) Côté Client
 * ============================================================================
 *
 * ARCHITECTURE CRYPTOGRAPHIQUE (PROTOCOLE SIGNAL — LIBSIGNAL-PROTOCOL-TYPESCRIPT) :
 * - Bibliothèque : `@privacyresearch/libsignal-protocol-typescript` (implémentation
 *   TypeScript/WebCrypto du protocole Signal : X3DH + Double Ratchet).
 * - Protocole unique autorisé : `SIGNAL_X3DH_DOUBLERATCHET_AES256GCM_ECDSA`.
 *   Tout repli vers l'ancien schéma WebCrypto HKDF de groupe est supprimé et toute
 *   enveloppe portant un identifiant de protocole différent est rejetée (anti-downgrade).
 * - Messages directs et de groupe :
 *   `@privacyresearch/libsignal-protocol-typescript` implémentant le protocole Signal
 *   pair-à-pair (`SessionBuilder` X3DH + `SessionCipher` Double Ratchet, types 3 et 1),
 *   chaque message de canal (1-à-1 ou groupe) est chiffré individuellement pour chaque
 *   membre actif autorisé via sa session Signal dédiée (enveloppes Signal par destinataire).
 * - Pièces jointes et notes vocales :
 *   Chaque fichier binaire est chiffré côté client avec une clé symétrique aléatoire
 *   éphémère `AES-256-GCM` (256 bits) et un IV de 96 bits après bourrage à 4096 octets.
 *   Le blob chiffré est téléversé une seule fois sur `/api/blobs` (sans la clé), et la
 *   clé symétrique aléatoire (`attachmentKeyB64`) est distribuée exclusivement dans les
 *   enveloppes de message chiffrées par les sessions Signal des membres autorisés.
 * - Consommation et non-réutilisation des pré-clés à usage unique (One-Time PreKeys) :
 *   Lors de l'ouverture d'une session X3DH (`PreKeyWhisperMessage` type 3), la pré-clé
 *   à usage unique (`preKeyId`) est supprimée définitivement du `SignalProtocolStore`
 *   local et persistée comme consommée dans le trousseau chiffré. Toute tentative de
 *   réutilisation d'un `preKeyId` consommé pour initialiser une autre session est rejetée.
 * - Persistance sécurisée des sessions et pré-clés :
 *   L'état complet du `SignalProtocolStore` (sessions Double Ratchet sérialisées,
 *   identités distantes, pré-clés restantes et IDs consommés) est chiffré au repos
 *   dans `localStorage` par la clé maître `AES-GCM-256` non-extractible stockée dans
 *   `IndexedDB`, survivant aux rechargements du navigateur sans réinitialiser le ratchet.
 * ============================================================================
 */

import {
  KeyHelper,
  SessionBuilder,
  SessionCipher,
  SignalProtocolAddress,
  setWebCrypto,
} from '@privacyresearch/libsignal-protocol-typescript';
import * as libsignalProtobuf from '@privacyresearch/libsignal-protocol-protobuf-ts';

export const E2EE_PROTOCOL_IDENTIFIER = 'SIGNAL_X3DH_DOUBLERATCHET_AES256GCM_ECDSA';
export const LEGACY_UNSUPPORTED_PROTOCOL_IDENTIFIER = 'WEBCRYPTO_ECDH_HKDF_AES256GCM_ECDSA';

const WRAPPED_KEYSTORE_STORAGE_PREFIX = 'faso_secur_e2ee_wrapped_ks_v3_';
const SESSION_KEYSTORE_CACHE_PREFIX = 'faso_secur_e2ee_session_ks_v3_';
const LEGACY_KEYSTORE_STORAGE_PREFIX = 'faso_secur_e2ee_keystore_v2_';
const IDB_DATABASE_NAME = 'FasoSecurHardwareKeystoreDB';
const IDB_STORE_NAME = 'NonExtractableWrappingKeys';
const INITIAL_ONE_TIME_PREKEY_COUNT = 20;

const inMemoryWrappingKeys = new Map();
const inMemoryKeystores = new Map();
const activeSignalStores = new Map();
const establishedGroupEpochs = new Map();
const channelActiveMembersCache = new Map();

function ensureSignalWebCryptoInitialized() {
  if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
    setWebCrypto(globalThis.crypto);
  } else if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
    setWebCrypto(window.crypto);
  }
}
ensureSignalWebCryptoInitialized();

// ============================================================================
// Utilitaires d'encodage Base64 / Hex <-> ArrayBuffer / Uint8Array
// ============================================================================

export function bytesToBase64(bytes) {
  const uint8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  for (let i = 0; i < uint8.byteLength; i += 1) {
    binary += String.fromCharCode(uint8[i]);
  }
  return window.btoa(binary);
}

export function base64ToBytes(base64Str) {
  const binary = window.atob(base64Str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function bytesToHex(bytes) {
  const uint8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return Array.from(uint8)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToBytes(hexStr) {
  const clean = String(hexStr || '').trim();
  if (clean.length % 2 !== 0) {
    throw new Error('Chaîne hexadécimale invalide');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    out[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  return out;
}

function uint8ToArrayBuffer(uint8) {
  return uint8.buffer.slice(uint8.byteOffset, uint8.byteOffset + uint8.byteLength);
}

function base64ToArrayBuffer(base64Str) {
  return uint8ToArrayBuffer(base64ToBytes(base64Str));
}

function arrayBufferToBase64(buffer) {
  return bytesToBase64(new Uint8Array(buffer));
}

function binaryStringToBytes(str) {
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i += 1) {
    bytes[i] = str.charCodeAt(i) & 0xff;
  }
  return bytes;
}

async function computeSafetyNumber30Digits(matricule, identityPublicKeyStr, signingPublicKeyStr) {
  const payload = `${matricule.trim().toUpperCase()}::${identityPublicKeyStr}::${signingPublicKeyStr}`;
  const digestBuf = await window.crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(payload)
  );
  const d = new Uint8Array(digestBuf);
  const groups = [];
  for (let i = 0; i < 6; i += 1) {
    const chunk =
      ((d[i * 4] << 24) >>> 0) +
      ((d[i * 4 + 1] << 16) >>> 0) +
      ((d[i * 4 + 2] << 8) >>> 0) +
      (d[i * 4 + 3] >>> 0);
    groups.push(String(chunk % 100000).padStart(5, '0'));
  }
  return groups.join(' ');
}

// ============================================================================
// SignalProtocolStore — Implémentation persistante pour libsignal-protocol-ts
// ============================================================================

export class SignalProtocolStore {
  constructor(initialState = {}) {
    this.identityKeyPair = initialState.identityKeyPair || null;
    this.registrationId = initialState.registrationId || 1;
    this.preKeys = new Map();
    this.signedPreKeys = new Map();
    this.sessions = new Map();
    this.identities = new Map();
    this.consumedPreKeys = new Map(); // keyId (string) -> baseKeyB64 (string)
    this.onStateChanged = null;
  }

  async getIdentityKeyPair() {
    return this.identityKeyPair;
  }

  async getLocalRegistrationId() {
    return this.registrationId;
  }

  async isTrustedIdentity(identifier, identityKey) {
    if (!identifier || !identityKey) return false;
    const existing = this.identities.get(identifier);
    const incomingB64 = arrayBufferToBase64(identityKey);
    if (!existing) {
      this.identities.set(identifier, incomingB64);
      return true;
    }
    return existing === incomingB64;
  }

  async saveIdentity(encodedAddress, publicKey) {
    const incomingB64 = arrayBufferToBase64(publicKey);
    const existing = this.identities.get(encodedAddress);
    this.identities.set(encodedAddress, incomingB64);
    const baseName = String(encodedAddress).split('.')[0];
    if (baseName && !this.identities.has(baseName)) {
      this.identities.set(baseName, incomingB64);
    }
    if (typeof this.onStateChanged === 'function') {
      this.onStateChanged();
    }
    return Boolean(existing && existing !== incomingB64);
  }

  async loadPreKey(keyId) {
    return this.preKeys.get(String(keyId));
  }

  async storePreKey(keyId, keyPair) {
    this.preKeys.set(String(keyId), {
      pubKey: keyPair.pubKey,
      privKey: keyPair.privKey,
    });
    if (typeof this.onStateChanged === 'function') {
      this.onStateChanged();
    }
  }

  async removePreKey(keyId) {
    const keyStr = String(keyId);
    this.preKeys.delete(keyStr);
    if (!this.consumedPreKeys.has(keyStr)) {
      this.consumedPreKeys.set(keyStr, 'CONSUMED');
    }
    if (typeof this.onStateChanged === 'function') {
      this.onStateChanged();
    }
  }

  markPreKeyConsumedByBaseKey(keyId, baseKeyB64) {
    const keyStr = String(keyId);
    this.preKeys.delete(keyStr);
    this.consumedPreKeys.set(keyStr, baseKeyB64 || 'CONSUMED');
    if (typeof this.onStateChanged === 'function') {
      this.onStateChanged();
    }
  }

  isPreKeyConsumedForDifferentBaseKey(keyId, incomingBaseKeyB64) {
    const keyStr = String(keyId);
    if (this.consumedPreKeys.has(keyStr)) {
      const recordedBaseKey = this.consumedPreKeys.get(keyStr);
      if (recordedBaseKey === 'CONSUMED' || recordedBaseKey !== incomingBaseKeyB64) {
        return true;
      }
    }
    return false;
  }

  async loadSignedPreKey(keyId) {
    return this.signedPreKeys.get(String(keyId));
  }

  async storeSignedPreKey(keyId, keyPair) {
    this.signedPreKeys.set(String(keyId), {
      pubKey: keyPair.pubKey,
      privKey: keyPair.privKey,
    });
    if (typeof this.onStateChanged === 'function') {
      this.onStateChanged();
    }
  }

  async removeSignedPreKey(keyId) {
    this.signedPreKeys.delete(String(keyId));
    if (typeof this.onStateChanged === 'function') {
      this.onStateChanged();
    }
  }

  async loadSession(identifier) {
    return this.sessions.get(String(identifier));
  }

  async storeSession(identifier, record) {
    this.sessions.set(String(identifier), record);
    if (typeof this.onStateChanged === 'function') {
      this.onStateChanged();
    }
  }

  async removeSession(identifier) {
    this.sessions.delete(String(identifier));
    if (typeof this.onStateChanged === 'function') {
      this.onStateChanged();
    }
  }

  async removeAllSessions(identifier) {
    for (const key of Array.from(this.sessions.keys())) {
      if (key.startsWith(String(identifier))) {
        this.sessions.delete(key);
      }
    }
    if (typeof this.onStateChanged === 'function') {
      this.onStateChanged();
    }
  }

  exportSerializableState() {
    const preKeysArr = [];
    for (const [keyId, kp] of this.preKeys.entries()) {
      preKeysArr.push({
        keyId: Number(keyId),
        pubKeyB64: arrayBufferToBase64(kp.pubKey),
        privKeyB64: arrayBufferToBase64(kp.privKey),
      });
    }
    const sessionsObj = {};
    for (const [addr, serializedRecord] of this.sessions.entries()) {
      sessionsObj[addr] = serializedRecord;
    }
    const identitiesObj = {};
    for (const [id, pubB64] of this.identities.entries()) {
      identitiesObj[id] = pubB64;
    }
    const consumedObj = {};
    for (const [keyId, baseKeyB64] of this.consumedPreKeys.entries()) {
      consumedObj[keyId] = baseKeyB64;
    }
    return {
      signalPreKeys: preKeysArr,
      signalSessions: sessionsObj,
      signalIdentities: identitiesObj,
      signalConsumedPreKeys: consumedObj,
    };
  }
}

export function createSignalStoreFromKeystore(keystore) {
  return getOrHydrateSignalStore(keystore);
}

function hydrateSignalStoreFromKeystore(keystore) {
  const store = new SignalProtocolStore({
    registrationId: keystore.signalRegistrationId || 1,
    identityKeyPair: {
      pubKey: base64ToArrayBuffer(keystore.signalIdentityKeyPair.pubKeyB64),
      privKey: base64ToArrayBuffer(keystore.signalIdentityKeyPair.privKeyB64),
    },
  });

  if (keystore.signalSignedPreKey) {
    store.signedPreKeys.set(String(keystore.signalSignedPreKey.keyId), {
      pubKey: base64ToArrayBuffer(keystore.signalSignedPreKey.pubKeyB64),
      privKey: base64ToArrayBuffer(keystore.signalSignedPreKey.privKeyB64),
    });
  }

  if (Array.isArray(keystore.signalPreKeys)) {
    for (const pk of keystore.signalPreKeys) {
      store.preKeys.set(String(pk.keyId), {
        pubKey: base64ToArrayBuffer(pk.pubKeyB64),
        privKey: base64ToArrayBuffer(pk.privKeyB64),
      });
    }
  }

  if (keystore.signalSessions && typeof keystore.signalSessions === 'object') {
    for (const [addr, rec] of Object.entries(keystore.signalSessions)) {
      if (typeof rec === 'string') {
        store.sessions.set(addr, rec);
      }
    }
  }

  if (keystore.signalIdentities && typeof keystore.signalIdentities === 'object') {
    for (const [id, pubB64] of Object.entries(keystore.signalIdentities)) {
      if (typeof pubB64 === 'string') {
        store.identities.set(id, pubB64);
      }
    }
  }

  if (keystore.signalConsumedPreKeys && typeof keystore.signalConsumedPreKeys === 'object') {
    for (const [keyId, baseKeyB64] of Object.entries(keystore.signalConsumedPreKeys)) {
      store.consumedPreKeys.set(String(keyId), String(baseKeyB64));
      store.preKeys.delete(String(keyId));
    }
  }

  if (keystore.signalSelfDevice) {
    const selfStore = new SignalProtocolStore({
      registrationId: keystore.signalSelfDevice.registrationId || 2,
      identityKeyPair: {
        pubKey: base64ToArrayBuffer(keystore.signalSelfDevice.identityKeyPair.pubKeyB64),
        privKey: base64ToArrayBuffer(keystore.signalSelfDevice.identityKeyPair.privKeyB64),
      },
    });
    selfStore.signedPreKeys.set(String(keystore.signalSelfDevice.signedPreKey.keyId), {
      pubKey: base64ToArrayBuffer(keystore.signalSelfDevice.signedPreKey.pubKeyB64),
      privKey: base64ToArrayBuffer(keystore.signalSelfDevice.signedPreKey.privKeyB64),
    });
    if (Array.isArray(keystore.signalSelfDevice.preKeys)) {
      for (const pk of keystore.signalSelfDevice.preKeys) {
        selfStore.preKeys.set(String(pk.keyId), {
          pubKey: base64ToArrayBuffer(pk.pubKeyB64),
          privKey: base64ToArrayBuffer(pk.privKeyB64),
        });
      }
    }
    if (keystore.signalSelfDevice.sessions && typeof keystore.signalSelfDevice.sessions === 'object') {
      for (const [addr, rec] of Object.entries(keystore.signalSelfDevice.sessions)) {
        selfStore.sessions.set(addr, rec);
      }
    }
    if (keystore.signalSelfDevice.identities && typeof keystore.signalSelfDevice.identities === 'object') {
      for (const [id, pubB64] of Object.entries(keystore.signalSelfDevice.identities)) {
        selfStore.identities.set(id, pubB64);
      }
    }
    if (keystore.signalSelfDevice.consumedPreKeys && typeof keystore.signalSelfDevice.consumedPreKeys === 'object') {
      for (const [keyId, baseKeyB64] of Object.entries(keystore.signalSelfDevice.consumedPreKeys)) {
        selfStore.consumedPreKeys.set(String(keyId), String(baseKeyB64));
        selfStore.preKeys.delete(String(keyId));
      }
    }
    store.selfDeviceStore = selfStore;
  }

  return store;
}

export function getOrHydrateSignalStore(keystore) {
  if (!keystore || !keystore.matricule) {
    throw new Error('Keystore agent invalide ou absent.');
  }
  const existing = activeSignalStores.get(keystore.matricule);
  if (existing) {
    return existing;
  }
  const hydrated = hydrateSignalStoreFromKeystore(keystore);
  activeSignalStores.set(keystore.matricule, hydrated);
  return hydrated;
}

async function syncAndPersistSignalStore(store, keystore) {
  if (!store || !keystore) return;
  const exported = store.exportSerializableState();
  keystore.signalPreKeys = exported.signalPreKeys;
  keystore.signalSessions = exported.signalSessions;
  keystore.signalIdentities = exported.signalIdentities;
  keystore.signalConsumedPreKeys = exported.signalConsumedPreKeys;

  if (store.selfDeviceStore && keystore.signalSelfDevice) {
    const selfExported = store.selfDeviceStore.exportSerializableState();
    keystore.signalSelfDevice.preKeys = selfExported.signalPreKeys;
    keystore.signalSelfDevice.sessions = selfExported.signalSessions;
    keystore.signalSelfDevice.identities = selfExported.signalIdentities;
    keystore.signalSelfDevice.consumedPreKeys = selfExported.signalConsumedPreKeys;
  }

  inMemoryKeystores.set(keystore.matricule, keystore);
  await persistKeystoreToStorage(keystore);
}

// ============================================================================
// Génération du matériel cryptographique Signal (X3DH + Double Ratchet)
// ============================================================================

async function generateSignalKeyBundleMaterial() {
  ensureSignalWebCryptoInitialized();
  const registrationId = KeyHelper.generateRegistrationId();
  const identityKeyPair = await KeyHelper.generateIdentityKeyPair();
  const signedPreKeyId = 1;
  const signedPreKey = await KeyHelper.generateSignedPreKey(identityKeyPair, signedPreKeyId);

  const preKeys = [];
  for (let id = 1; id <= INITIAL_ONE_TIME_PREKEY_COUNT; id += 1) {
    const pk = await KeyHelper.generatePreKey(id);
    preKeys.push({
      keyId: pk.keyId,
      pubKeyB64: arrayBufferToBase64(pk.keyPair.pubKey),
      privKeyB64: arrayBufferToBase64(pk.keyPair.privKey),
    });
  }

  const selfRegistrationId = KeyHelper.generateRegistrationId();
  const selfIdentityKeyPair = await KeyHelper.generateIdentityKeyPair();
  const selfSignedPreKey = await KeyHelper.generateSignedPreKey(selfIdentityKeyPair, 1);
  const selfPreKey = await KeyHelper.generatePreKey(1);

  const identityPubB64 = arrayBufferToBase64(identityKeyPair.pubKey);
  const identityPrivB64 = arrayBufferToBase64(identityKeyPair.privKey);

  return {
    signalRegistrationId: registrationId,
    signalIdentityPublicB64: identityPubB64,
    signalIdentityPrivateB64: identityPrivB64,
    signalIdentityKeyPair: {
      pubKeyB64: identityPubB64,
      privKeyB64: identityPrivB64,
    },
    signalSignedPreKey: {
      keyId: signedPreKey.keyId,
      pubKeyB64: arrayBufferToBase64(signedPreKey.keyPair.pubKey),
      privKeyB64: arrayBufferToBase64(signedPreKey.keyPair.privKey),
      signatureB64: arrayBufferToBase64(signedPreKey.signature),
    },
    signalPreKeys: preKeys,
    signalSessions: {},
    signalIdentities: {},
    signalConsumedPreKeys: {},
    signalSelfDevice: {
      registrationId: selfRegistrationId,
      identityKeyPair: {
        pubKeyB64: arrayBufferToBase64(selfIdentityKeyPair.pubKey),
        privKeyB64: arrayBufferToBase64(selfIdentityKeyPair.privKey),
      },
      signedPreKey: {
        keyId: selfSignedPreKey.keyId,
        pubKeyB64: arrayBufferToBase64(selfSignedPreKey.keyPair.pubKey),
        privKeyB64: arrayBufferToBase64(selfSignedPreKey.keyPair.privKey),
        signatureB64: arrayBufferToBase64(selfSignedPreKey.signature),
      },
      preKeys: [
        {
          keyId: selfPreKey.keyId,
          pubKeyB64: arrayBufferToBase64(selfPreKey.keyPair.pubKey),
          privKeyB64: arrayBufferToBase64(selfPreKey.keyPair.privKey),
        },
      ],
      sessions: {},
      identities: {},
      consumedPreKeys: {},
    },
    decryptedMessageVault: {},
  };
}

// ============================================================================
// Bourrage déterministe (Traffic-Analysis Mitigation Padding)
// ============================================================================

function padPlaintextObjectTo256Bytes(plaintextObj) {
  const encoder = new TextEncoder();
  const coreJsonBytes = encoder.encode(JSON.stringify(plaintextObj));
  const totalFramedLen = 4 + coreJsonBytes.byteLength;
  const blockMultiple = 256;
  const paddedLen = Math.ceil(totalFramedLen / blockMultiple) * blockMultiple;

  const paddedBuffer = new Uint8Array(paddedLen);
  const view = new DataView(paddedBuffer.buffer);
  view.setUint32(0, coreJsonBytes.byteLength, false);
  paddedBuffer.set(coreJsonBytes, 4);

  if (paddedLen > totalFramedLen) {
    const randomPad = window.crypto.getRandomValues(new Uint8Array(paddedLen - totalFramedLen));
    paddedBuffer.set(randomPad, totalFramedLen);
  }
  return paddedBuffer;
}

function unpadPlaintextObjectFrom256Bytes(decryptedBuffer) {
  const bytes = decryptedBuffer instanceof Uint8Array ? decryptedBuffer : new Uint8Array(decryptedBuffer);
  if (bytes.byteLength >= 4) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const coreLen = view.getUint32(0, false);
    if (coreLen > 0 && coreLen <= bytes.byteLength - 4) {
      try {
        const slice = bytes.subarray(4, 4 + coreLen);
        return JSON.parse(new TextDecoder().decode(slice));
      } catch {
        // Fallback if unframed JSON
      }
    }
  }
  return JSON.parse(new TextDecoder().decode(bytes));
}

function padAttachmentTo4096Bytes(rawString) {
  const encoder = new TextEncoder();
  const coreBytes = encoder.encode(rawString);
  const totalFramedLen = 4 + coreBytes.byteLength;
  const blockMultiple = 4096;
  const paddedLen = Math.ceil(totalFramedLen / blockMultiple) * blockMultiple;

  const paddedBuffer = new Uint8Array(paddedLen);
  const view = new DataView(paddedBuffer.buffer);
  view.setUint32(0, coreBytes.byteLength, false);
  paddedBuffer.set(coreBytes, 4);

  if (paddedLen > totalFramedLen) {
    const randomPad = new Uint8Array(paddedLen - totalFramedLen);
    for (let offset = 0; offset < randomPad.byteLength; offset += 65536) {
      const chunkLen = Math.min(65536, randomPad.byteLength - offset);
      window.crypto.getRandomValues(randomPad.subarray(offset, offset + chunkLen));
    }
    paddedBuffer.set(randomPad, totalFramedLen);
  }
  return paddedBuffer;
}

function unpadAttachmentFrom4096Bytes(decryptedBuffer) {
  const bytes = decryptedBuffer instanceof Uint8Array ? decryptedBuffer : new Uint8Array(decryptedBuffer);
  if (bytes.byteLength >= 4) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const coreLen = view.getUint32(0, false);
    if (coreLen > 0 && coreLen <= bytes.byteLength - 4) {
      const slice = bytes.subarray(4, 4 + coreLen);
      return new TextDecoder().decode(slice);
    }
  }
  return new TextDecoder().decode(bytes);
}

// ============================================================================
// Trousseau Matériel IndexedDB (Clé maîtresse AES-GCM-256 non-extractible)
// ============================================================================

async function getOrCreateIndexedDBNonExtractableKey(matricule) {
  if (typeof window !== 'undefined' && window.indexedDB) {
    try {
      const db = await new Promise((resolve, reject) => {
        const req = window.indexedDB.open(IDB_DATABASE_NAME, 1);
        req.onupgradeneeded = () => {
          const d = req.result;
          if (!d.objectStoreNames.contains(IDB_STORE_NAME)) {
            d.createObjectStore(IDB_STORE_NAME);
          }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });

      const existingKey = await new Promise((resolve, reject) => {
        const tx = db.transaction(IDB_STORE_NAME, 'readonly');
        const store = tx.objectStore(IDB_STORE_NAME);
        const getReq = store.get(matricule);
        getReq.onsuccess = () => resolve(getReq.result || null);
        getReq.onerror = () => reject(getReq.error);
      });

      if (existingKey) {
        db.close();
        return existingKey;
      }

      const masterKey = await window.crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );

      await new Promise((resolve, reject) => {
        const tx = db.transaction(IDB_STORE_NAME, 'readwrite');
        const store = tx.objectStore(IDB_STORE_NAME);
        const putReq = store.put(masterKey, matricule);
        putReq.onsuccess = () => resolve(true);
        putReq.onerror = () => reject(putReq.error);
      });
      db.close();
      return masterKey;
    } catch {
      // Fallback to in-memory non-extractable CryptoKey if IndexedDB is unavailable
    }
  }

  if (inMemoryWrappingKeys.has(matricule)) {
    return inMemoryWrappingKeys.get(matricule);
  }
  const memKey = await window.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  inMemoryWrappingKeys.set(matricule, memKey);
  return memKey;
}

async function wrapKeystoreObject(keystore, wrappingKey) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(keystore));
  const cipherBuf = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    wrappingKey,
    encoded
  );
  return JSON.stringify({
    v: 'WRAPPED_IDB_AES256GCM_V3',
    encryptedAtRest: true,
    ivB64: bytesToBase64(iv),
    ciphertextB64: bytesToBase64(new Uint8Array(cipherBuf)),
  });
}

async function unwrapKeystoreObject(wrappedJsonStr, wrappingKey) {
  const parsed = JSON.parse(wrappedJsonStr);
  if (!parsed || parsed.v !== 'WRAPPED_IDB_AES256GCM_V3') {
    throw new Error('Format de trousseau chiffré non reconnu');
  }
  const iv = base64ToBytes(parsed.ivB64);
  const cipherBytes = base64ToBytes(parsed.ciphertextB64);
  const plainBuf = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    wrappingKey,
    cipherBytes
  );
  return JSON.parse(new TextDecoder().decode(plainBuf));
}

async function persistKeystoreToStorage(keystore) {
  if (!keystore || !keystore.matricule) return;
  try {
    const wrappingKey = await getOrCreateIndexedDBNonExtractableKey(keystore.matricule);
    const wrappedPayload = await wrapKeystoreObject(keystore, wrappingKey);
    const wrappedStorageKey = `${WRAPPED_KEYSTORE_STORAGE_PREFIX}${keystore.matricule}`;
    const sessionCacheKey = `${SESSION_KEYSTORE_CACHE_PREFIX}${keystore.matricule}`;
    window.localStorage.setItem(wrappedStorageKey, wrappedPayload);
    if (window.sessionStorage) {
      window.sessionStorage.setItem(sessionCacheKey, wrappedPayload);
    }
  } catch {
    // Ignore storage quota errors in constrained environments
  }
}

function getActiveAgentKeystore(matricule = null) {
  if (matricule && inMemoryKeystores.has(matricule)) {
    return inMemoryKeystores.get(matricule);
  }
  const firstEntry = inMemoryKeystores.values().next();
  return firstEntry.done ? null : firstEntry.value;
}

async function importEcdsaPublicKeyFromMember(signingKeyOrJwk) {
  if (!signingKeyOrJwk) {
    throw new Error('Clé publique ECDSA absente');
  }
  if (typeof signingKeyOrJwk === 'object' && signingKeyOrJwk.kty === 'EC') {
    return window.crypto.subtle.importKey(
      'jwk',
      signingKeyOrJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
  }
  const str = String(signingKeyOrJwk).trim();
  if (str.startsWith('{')) {
    const jwk = JSON.parse(str);
    return window.crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
  }
  return window.crypto.subtle.importKey(
    'raw',
    base64ToBytes(str),
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );
}

// ============================================================================
// 1. Initialisation, génération et restauration du trousseau E2EE de l'agent
// ============================================================================

export async function initializeAgentKeystore(matricule) {
  try {
    window.localStorage.removeItem(`${LEGACY_KEYSTORE_STORAGE_PREFIX}${matricule}`);
  } catch {
    // ignore
  }

  if (inMemoryKeystores.has(matricule)) {
    const memKs = inMemoryKeystores.get(matricule);
    getOrHydrateSignalStore(memKs);
    return memKs;
  }

  const wrappingKey = await getOrCreateIndexedDBNonExtractableKey(matricule);
  const wrappedStorageKey = `${WRAPPED_KEYSTORE_STORAGE_PREFIX}${matricule}`;
  const sessionCacheKey = `${SESSION_KEYSTORE_CACHE_PREFIX}${matricule}`;

  const rawWrapped =
    (window.sessionStorage && window.sessionStorage.getItem(sessionCacheKey)) ||
    window.localStorage.getItem(wrappedStorageKey);

  if (rawWrapped) {
    try {
      const parsed = await unwrapKeystoreObject(rawWrapped, wrappingKey);
      if (
        parsed &&
        parsed.signingPrivateJwk &&
        parsed.signingPublicJwk &&
        parsed.signalIdentityKeyPair &&
        parsed.signalSignedPreKey &&
        Array.isArray(parsed.signalPreKeys) &&
        parsed.signalSelfDevice
      ) {
        parsed.signalSessions = parsed.signalSessions || {};
        parsed.signalIdentities = parsed.signalIdentities || {};
        parsed.signalConsumedPreKeys = parsed.signalConsumedPreKeys || {};
        parsed.decryptedMessageVault = parsed.decryptedMessageVault || {};
        parsed.establishedEpochs = parsed.establishedEpochs || {};
        for (const [epKey, val] of Object.entries(parsed.establishedEpochs)) {
          if (val) establishedGroupEpochs.set(epKey, true);
        }
        inMemoryKeystores.set(matricule, parsed);
        activeSignalStores.delete(matricule);
        getOrHydrateSignalStore(parsed);
        return parsed;
      }
    } catch {
      // Régénération propre si le trousseau est corrompu
    }
  }

  // Paire de clés d'identité ECDSA P-256 (Authentification annuaire & Reçus probants)
  const signingKeyPair = await window.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  // Paires de clés P-256 publiées dans l'annuaire serveur (/api/e2ee/keys)
  const identityEcdhKeyPair = await window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );
  const directorySignedPreKeyPair = await window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );

  const signingPrivateJwk = await window.crypto.subtle.exportKey('jwk', signingKeyPair.privateKey);
  const signingPublicJwk = await window.crypto.subtle.exportKey('jwk', signingKeyPair.publicKey);
  const identityPublicJwk = await window.crypto.subtle.exportKey('jwk', identityEcdhKeyPair.publicKey);
  const signedPreKeyPublicJwk = await window.crypto.subtle.exportKey('jwk', directorySignedPreKeyPair.publicKey);
  const signingPublicRaw = await window.crypto.subtle.exportKey('raw', signingKeyPair.publicKey);

  // Signature ECDSA P-256 de la pré-clé d'annuaire (vérifiée par POST /api/e2ee/keys)
  const signedPreKeyPublicStr = JSON.stringify(signedPreKeyPublicJwk);
  const preKeySigBuf = await window.crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    signingKeyPair.privateKey,
    new TextEncoder().encode(signedPreKeyPublicStr)
  );
  const signedPreKeySignatureHex = bytesToHex(new Uint8Array(preKeySigBuf));

  // Génération du bundle Signal (X3DH + Double Ratchet + 20 One-Time PreKeys)
  const signalMaterial = await generateSignalKeyBundleMaterial();

  const identityPublicStr = JSON.stringify(identityPublicJwk);
  const signingPublicStr = JSON.stringify(signingPublicJwk);
  const safetyNumber = await computeSafetyNumber30Digits(
    matricule,
    identityPublicStr,
    signingPublicStr
  );

  const digestBuffer = await window.crypto.subtle.digest(
    'SHA-256',
    base64ToArrayBuffer(signalMaterial.signalIdentityKeyPair.pubKeyB64)
  );
  const hashBytes = new Uint8Array(digestBuffer);
  const fingerprintHex = Array.from(hashBytes.slice(0, 8))
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join(':');

  const keystore = {
    matricule,
    protocol: E2EE_PROTOCOL_IDENTIFIER,
    signingPrivateJwk,
    signingPublicJwk,
    signingPublicKeyB64: bytesToBase64(signingPublicRaw),
    identityPublicJwk,
    signedPreKeyPublicJwk,
    signedPreKeySignatureHex,
    safetyNumber,
    keyFingerprint: fingerprintHex,
    establishedEpochs: {},
    ...signalMaterial,
    createdAt: new Date().toISOString(),
  };

  inMemoryKeystores.set(matricule, keystore);
  activeSignalStores.delete(matricule);
  getOrHydrateSignalStore(keystore);
  await persistKeystoreToStorage(keystore);
  return keystore;
}

/**
 * Formate le bundle public X3DH Signal et les clés publiques d'annuaire à publier
 * sur `/api/e2ee/keys`. N'expose que les clés publiques et les One-Time PreKeys non consommées.
 */
export function getPublicBundleForServer(keystore) {
  const store = getOrHydrateSignalStore(keystore);
  const exported = store.exportSerializableState();
  const availablePreKeys = exported.signalPreKeys.map((pk) => ({
    keyId: pk.keyId,
    publicKeyB64: pk.pubKeyB64,
  }));
  const primaryPreKey = availablePreKeys[0] || null;

  return {
    identity_public_key: JSON.stringify(keystore.identityPublicJwk),
    signing_public_key: JSON.stringify(keystore.signingPublicJwk),
    signed_prekey_public: JSON.stringify(keystore.signedPreKeyPublicJwk),
    signed_prekey_signature: keystore.signedPreKeySignatureHex,
    one_time_prekeys_json: JSON.stringify({
      protocol: E2EE_PROTOCOL_IDENTIFIER,
      signal_prekey_bundle: {
        registrationId: keystore.signalRegistrationId,
        identityKeyB64: keystore.signalIdentityKeyPair.pubKeyB64,
        signedPreKey: {
          keyId: keystore.signalSignedPreKey.keyId,
          publicKeyB64: keystore.signalSignedPreKey.pubKeyB64,
          signatureB64: keystore.signalSignedPreKey.signatureB64,
        },
        preKey: primaryPreKey,
        oneTimePreKeys: availablePreKeys,
      },
    }),
  };
}

// ============================================================================
// 2. Sessions Signal Pair-à-Pair (X3DH SessionBuilder + Double Ratchet SessionCipher)
// ============================================================================

/**
 * Extrait et consomme une One-Time PreKey depuis le bundle public d'un membre.
 * Garantit qu'un même initiateur ne réutilise jamais la même One-Time PreKey.
 */
export function extractMemberSignalPreKeyBundle(member) {
  if (!member || !member.e2ee_one_time_prekeys_json) {
    throw new Error(
      `Le membre ${member?.matricule || 'inconnu'} ne dispose pas d'un bundle Signal X3DH valide.`
    );
  }
  let parsed;
  try {
    parsed =
      typeof member.e2ee_one_time_prekeys_json === 'string'
        ? JSON.parse(member.e2ee_one_time_prekeys_json)
        : member.e2ee_one_time_prekeys_json;
  } catch {
    throw new Error(`Bundle Signal JSON invalide pour ${member?.matricule || 'inconnu'}.`);
  }

  const sigBundle = parsed?.signal_prekey_bundle;
  if (!sigBundle || !sigBundle.identityKeyB64 || !sigBundle.signedPreKey) {
    throw new Error(
      `Bundle Signal X3DH incomplet pour ${member?.matricule || 'inconnu'}. Aucun repli autorisé.`
    );
  }

  // Sélection et consommation d'une One-Time PreKey disponible dans le bundle
  let selectedPreKey = null;
  if (Array.isArray(sigBundle.oneTimePreKeys) && sigBundle.oneTimePreKeys.length > 0) {
    selectedPreKey = sigBundle.oneTimePreKeys.shift();
    sigBundle.preKey = sigBundle.oneTimePreKeys[0] || null;
    member.e2ee_one_time_prekeys_json = JSON.stringify(parsed);
  } else if (sigBundle.preKey && sigBundle.preKey.publicKeyB64) {
    selectedPreKey = sigBundle.preKey;
    sigBundle.preKey = null;
    member.e2ee_one_time_prekeys_json = JSON.stringify(parsed);
  }

  const deviceBundle = {
    registrationId: Number(sigBundle.registrationId || 1),
    identityKey: base64ToArrayBuffer(sigBundle.identityKeyB64),
    signedPreKey: {
      keyId: Number(sigBundle.signedPreKey.keyId || 1),
      publicKey: base64ToArrayBuffer(sigBundle.signedPreKey.publicKeyB64),
      signature: base64ToArrayBuffer(sigBundle.signedPreKey.signatureB64),
    },
  };

  if (selectedPreKey && selectedPreKey.publicKeyB64) {
    deviceBundle.preKey = {
      keyId: Number(selectedPreKey.keyId || 1),
      publicKey: base64ToArrayBuffer(selectedPreKey.publicKeyB64),
    };
  }

  return deviceBundle;
}

export async function establishSignalDirectSession(localStore, remoteMatricule, remoteMemberObj) {
  ensureSignalWebCryptoInitialized();
  const address = new SignalProtocolAddress(remoteMatricule, 1);
  const deviceBundle = extractMemberSignalPreKeyBundle(remoteMemberObj);
  const builder = new SessionBuilder(localStore, address);
  await builder.processPreKey(deviceBundle);
  const ks = getActiveAgentKeystore(
    Array.from(activeSignalStores.entries()).find(([, st]) => st === localStore)?.[0]
  );
  if (ks) {
    await syncAndPersistSignalStore(localStore, ks);
  }
  return true;
}

export async function hasEstablishedSignalSession(keystore, remoteMatricule) {
  if (!keystore || !remoteMatricule) return false;
  try {
    const store = getOrHydrateSignalStore(keystore);
    const address = new SignalProtocolAddress(remoteMatricule, 1);
    const session = await store.loadSession(address.toString());
    return Boolean(session);
  } catch {
    return false;
  }
}

export async function encryptSignalDirectMessage({
  localStore,
  remoteMatricule,
  plaintextObject,
  keystore,
}) {
  ensureSignalWebCryptoInitialized();
  const address = new SignalProtocolAddress(remoteMatricule, 1);
  const cipher = new SessionCipher(localStore, address);
  const paddedBytes = padPlaintextObjectTo256Bytes(plaintextObject);
  const encrypted = await cipher.encrypt(uint8ToArrayBuffer(paddedBytes));
  const bodyB64 = window.btoa(encrypted.body);

  const signingKey = await window.crypto.subtle.importKey(
    'jwk',
    keystore.signingPrivateJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );
  const sigInput = new TextEncoder().encode(
    `SIGNAL_DIRECT:${keystore.matricule}:${remoteMatricule}:${encrypted.type}:${bodyB64}`
  );
  const sigBuf = await window.crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    signingKey,
    sigInput
  );

  await syncAndPersistSignalStore(localStore, keystore);

  return {
    e2ee_protocol: E2EE_PROTOCOL_IDENTIFIER,
    signal_message_type: encrypted.type,
    ciphertext_b64: bodyB64,
    registration_id: encrypted.registrationId,
    ecdsa_signature_hex: bytesToHex(new Uint8Array(sigBuf)),
  };
}

export async function decryptSignalDirectMessage({
  localStore,
  senderMatricule,
  recipientMatricule,
  envelope,
  senderSigningPublicJwk,
}) {
  try {
    if (!envelope || envelope.e2ee_protocol !== E2EE_PROTOCOL_IDENTIFIER) {
      return { decryptedOk: false, signatureVerified: false };
    }
    const verifyKey = await importEcdsaPublicKeyFromMember(senderSigningPublicJwk);
    const sigInput = new TextEncoder().encode(
      `SIGNAL_DIRECT:${senderMatricule}:${recipientMatricule}:${envelope.signal_message_type}:${envelope.ciphertext_b64}`
    );
    const sigValid = await window.crypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      verifyKey,
      hexToBytes(envelope.ecdsa_signature_hex),
      sigInput
    );
    if (!sigValid) {
      return { decryptedOk: false, signatureVerified: false };
    }

    const remoteAddress = new SignalProtocolAddress(senderMatricule, 1);
    const decryptedBytes = await decryptBytesWithSignalSession(localStore, remoteAddress, {
      type: envelope.signal_message_type,
      bodyB64: envelope.ciphertext_b64,
    });
    const ks = getActiveAgentKeystore(recipientMatricule);
    if (ks) {
      await syncAndPersistSignalStore(localStore, ks);
    }
    return {
      decryptedOk: true,
      signatureVerified: true,
      content: unpadPlaintextObjectFrom256Bytes(decryptedBytes),
    };
  } catch (err) {
    return {
      decryptedOk: false,
      signatureVerified: false,
      errorDetail: err?.message || String(err),
    };
  }
}

async function ensureOutboundSignalSession(localStore, targetAddress, targetDeviceBundleFn) {
  const addressStr = targetAddress.toString();
  const existingRecord = await localStore.loadSession(addressStr);
  if (existingRecord) {
    return;
  }
  const deviceBundle = targetDeviceBundleFn();
  const builder = new SessionBuilder(localStore, targetAddress);
  await builder.processPreKey(deviceBundle);
}

async function encryptBytesWithSignalSession(localStore, targetAddress, plaintextBytes, targetDeviceBundleFn) {
  ensureSignalWebCryptoInitialized();
  await ensureOutboundSignalSession(localStore, targetAddress, targetDeviceBundleFn);
  const cipher = new SessionCipher(localStore, targetAddress);
  const encryptedMessage = await cipher.encrypt(uint8ToArrayBuffer(plaintextBytes));
  return {
    type: encryptedMessage.type,
    bodyB64: window.btoa(encryptedMessage.body),
    registrationId: encryptedMessage.registrationId,
  };
}

async function decryptBytesWithSignalSession(targetStore, remoteAddress, signalCiphertextObj) {
  ensureSignalWebCryptoInitialized();
  const cipher = new SessionCipher(targetStore, remoteAddress);
  const binaryBody = window.atob(signalCiphertextObj.bodyB64);

  if (Number(signalCiphertextObj.type) === 3) {
    // Vérification stricte de non-réutilisation des One-Time PreKeys (X3DH Anti-Replay)
    const rawBytes = binaryStringToBytes(binaryBody);
    const protoBytes = rawBytes.slice(1);
    const decodedPreKeyProto = libsignalProtobuf.PreKeyWhisperMessage.decode(protoBytes);
    const incomingPreKeyId = decodedPreKeyProto.preKeyId;
    const incomingBaseKeyB64 = bytesToBase64(decodedPreKeyProto.baseKey);

    if (incomingPreKeyId !== undefined && incomingPreKeyId !== null && incomingPreKeyId > 0) {
      if (targetStore.isPreKeyConsumedForDifferentBaseKey(incomingPreKeyId, incomingBaseKeyB64)) {
        throw new Error(
          `REJET SIGNAL X3DH : La pré-clé à usage unique #${incomingPreKeyId} a déjà été consommée et supprimée.`
        );
      }
      const existingRecordStr = await targetStore.loadSession(remoteAddress.toString());
      const hasAvailablePreKey = Boolean(await targetStore.loadPreKey(incomingPreKeyId));
      if (!hasAvailablePreKey && !existingRecordStr) {
        throw new Error(
          `REJET SIGNAL X3DH : Pré-clé à usage unique #${incomingPreKeyId} introuvable ou déjà consommée.`
        );
      }
    }

    const plainBuf = await cipher.decryptPreKeyWhisperMessage(binaryBody, 'binary');
    if (incomingPreKeyId !== undefined && incomingPreKeyId !== null && incomingPreKeyId > 0) {
      targetStore.markPreKeyConsumedByBaseKey(incomingPreKeyId, incomingBaseKeyB64);
    }
    return new Uint8Array(plainBuf);
  }

  const plainBuf = await cipher.decryptWhisperMessage(binaryBody, 'binary');
  return new Uint8Array(plainBuf);
}

function buildSelfDeviceBundle(keystore) {
  const selfDev = keystore.signalSelfDevice;
  const firstPreKey = Array.isArray(selfDev.preKeys) && selfDev.preKeys.length > 0 ? selfDev.preKeys[0] : null;
  const bundle = {
    registrationId: Number(selfDev.registrationId || 2),
    identityKey: base64ToArrayBuffer(selfDev.identityKeyPair.pubKeyB64),
    signedPreKey: {
      keyId: Number(selfDev.signedPreKey.keyId || 1),
      publicKey: base64ToArrayBuffer(selfDev.signedPreKey.pubKeyB64),
      signature: base64ToArrayBuffer(selfDev.signedPreKey.signatureB64),
    },
  };
  if (firstPreKey) {
    bundle.preKey = {
      keyId: Number(firstPreKey.keyId || 1),
      publicKey: base64ToArrayBuffer(firstPreKey.pubKeyB64),
    };
  }
  return bundle;
}

// ============================================================================
// Enveloppage Signal Pair-à-Pair d'un Secret d'Époque / Rotation (Sans Fallback)
// ============================================================================

export async function wrapSecretForMember(channelId, epoch, secretB64, member, senderKeystore = null) {
  const keystore = senderKeystore || getActiveAgentKeystore();
  if (!keystore) {
    throw new Error('Trousseau local non initialisé pour l’enveloppage Signal.');
  }
  const localStore = getOrHydrateSignalStore(keystore);
  const plainBytes = new TextEncoder().encode(
    JSON.stringify({
      channelId: Number(channelId),
      epoch: Number(epoch),
      secretB64,
      targetMatricule: member.matricule,
      senderMatricule: keystore.matricule,
    })
  );

  let signalEnvelope;
  if (member.matricule === keystore.matricule) {
    const selfAddress = new SignalProtocolAddress(`${keystore.matricule}__SELF`, 2);
    signalEnvelope = await encryptBytesWithSignalSession(
      localStore,
      selfAddress,
      plainBytes,
      () => buildSelfDeviceBundle(keystore)
    );
    signalEnvelope.isSelfArchive = true;
  } else {
    const remoteAddress = new SignalProtocolAddress(member.matricule, 1);
    signalEnvelope = await encryptBytesWithSignalSession(
      localStore,
      remoteAddress,
      plainBytes,
      () => extractMemberSignalPreKeyBundle(member)
    );
  }

  const ivLabel = `SIGNAL_X3DH_V3_TYPE_${signalEnvelope.type}`;
  const wrappedKeyB64 = signalEnvelope.bodyB64;

  const signingKey = await window.crypto.subtle.importKey(
    'jwk',
    keystore.signingPrivateJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );

  const wrapMsg = new TextEncoder().encode(
    `WRAP:${channelId}:${epoch}:${member.matricule}:${ivLabel}:${wrappedKeyB64}`
  );
  const sigBuf = await window.crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    signingKey,
    wrapMsg
  );

  await syncAndPersistSignalStore(localStore, keystore);

  return {
    senderMatricule: keystore.matricule,
    ivB64: ivLabel,
    wrappedKeyB64,
    signalType: signalEnvelope.type,
    isSelfArchive: Boolean(signalEnvelope.isSelfArchive),
    senderSignatureHex: bytesToHex(new Uint8Array(sigBuf)),
  };
}

export async function unwrapSecretFromBundle(channelId, epoch, recipientMatricule, bundleObj, activeMembers = [], myKeystore = null) {
  const keystore = myKeystore || getActiveAgentKeystore(recipientMatricule);
  if (!keystore) {
    throw new Error('Keystore local introuvable');
  }
  if (!bundleObj || !bundleObj.ivB64 || !bundleObj.ivB64.startsWith('SIGNAL_X3DH_V3_TYPE_')) {
    throw new Error(
      `Enveloppe de clé rejetée : protocole ${bundleObj?.ivB64 || 'inconnu'} non pris en charge (Signal requis).`
    );
  }

  const signalType = Number(bundleObj.signalType || bundleObj.ivB64.replace('SIGNAL_X3DH_V3_TYPE_', ''));
  const senderMember = activeMembers.find((m) => m.matricule === bundleObj.senderMatricule);
  const signingKeySource = senderMember
    ? senderMember.e2ee_signing_public_key
    : bundleObj.senderMatricule === keystore.matricule
      ? keystore.signingPublicJwk
      : null;

  if (!signingKeySource) {
    throw new Error('Émetteur du bundle Signal non reconnu dans l’annuaire du canal.');
  }

  if (bundleObj.senderSignatureHex) {
    const verifyKey = await importEcdsaPublicKeyFromMember(signingKeySource);
    const wrapMsg = new TextEncoder().encode(
      `WRAP:${channelId}:${epoch}:${recipientMatricule}:${bundleObj.ivB64}:${bundleObj.wrappedKeyB64}`
    );
    const isSigValid = await window.crypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      verifyKey,
      hexToBytes(bundleObj.senderSignatureHex),
      wrapMsg
    );
    if (!isSigValid) {
      throw new Error('Signature ECDSA P-256 du bundle Signal invalide.');
    }
  }

  const localStore = getOrHydrateSignalStore(keystore);
  let decryptedBytes;
  if (bundleObj.isSelfArchive || bundleObj.senderMatricule === keystore.matricule) {
    const senderAddrOnSelf = new SignalProtocolAddress(keystore.matricule, 1);
    decryptedBytes = await decryptBytesWithSignalSession(
      localStore.selfDeviceStore,
      senderAddrOnSelf,
      { type: signalType, bodyB64: bundleObj.wrappedKeyB64 }
    );
  } else {
    const remoteAddress = new SignalProtocolAddress(bundleObj.senderMatricule, 1);
    decryptedBytes = await decryptBytesWithSignalSession(
      localStore,
      remoteAddress,
      { type: signalType, bodyB64: bundleObj.wrappedKeyB64 }
    );
  }

  await syncAndPersistSignalStore(localStore, keystore);
  const decoded = JSON.parse(new TextDecoder().decode(decryptedBytes));
  return decoded.secretB64;
}

/**
 * Synchronise l'époque du canal et distribue/vérifie les enveloppes de session Signal
 * entre membres actifs du canal (`SessionBuilder` X3DH + `SessionCipher` Double Ratchet).
 */
export async function syncChannelGroupSecret(arg1, arg2, arg3) {
  // Supporte les deux conventions d'appel :
  // - syncChannelGroupSecret({ channel, keystore, publish, onConflictReload })
  // - syncChannelGroupSecret(channelObj, keystore, publishFn)
  let channel;
  let keystore;
  let publish;
  if (arg1 && typeof arg1 === 'object' && 'channel' in arg1) {
    channel = arg1.channel;
    keystore = arg1.keystore;
    publish = arg1.publish;
  } else {
    channel = arg1;
    keystore = arg2;
    publish = arg3;
  }

  if (!channel || !keystore) return false;
  const channelId = Number(channel.id);
  const epoch = Number(channel.crypto_epoch || 1);
  const activeMembers = (channel.active_members || []).filter((m) => !m.is_revoked);

  if (activeMembers.length > 0) {
    channelActiveMembersCache.set(`${channelId}:${epoch}`, activeMembers);
    channelActiveMembersCache.set(`${channelId}:latest`, activeMembers);
  }

  const epochKey = `${keystore.matricule}:${channelId}:${epoch}`;
  const epochBundlesForChannel = channel.encrypted_group_session_bundles?.[String(epoch)] || {};
  const myBundle = epochBundlesForChannel[keystore.matricule];

  if (myBundle) {
    if (!establishedGroupEpochs.get(epochKey)) {
      try {
        await unwrapSecretFromBundle(
          channelId,
          epoch,
          keystore.matricule,
          myBundle,
          activeMembers,
          keystore
        );
      } catch {
        // Session Signal déjà avancée au-delà de ce PreKeyWhisperMessage initial
      }
      establishedGroupEpochs.set(epochKey, true);
      keystore.establishedEpochs = keystore.establishedEpochs || {};
      keystore.establishedEpochs[epochKey] = true;
      await persistKeystoreToStorage(keystore);
    }
    return true;
  }

  if (typeof publish === 'function' && activeMembers.length > 0) {
    const epochSecretB64 = bytesToBase64(window.crypto.getRandomValues(new Uint8Array(32)));
    const wrappedByMatricule = {};
    for (const member of activeMembers) {
      if (!member.e2ee_one_time_prekeys_json && member.matricule !== keystore.matricule) {
        continue;
      }
      try {
        wrappedByMatricule[member.matricule] = await wrapSecretForMember(
          channelId,
          epoch,
          epochSecretB64,
          member,
          keystore
        );
      } catch {
        // Membre sans bundle Signal complet
      }
    }
    if (Object.keys(wrappedByMatricule).length > 0) {
      await publish(wrappedByMatricule, Object.keys(epochBundlesForChannel).length === 0);
      establishedGroupEpochs.set(epochKey, true);
      keystore.establishedEpochs = keystore.establishedEpochs || {};
      keystore.establishedEpochs[epochKey] = true;
      await persistKeystoreToStorage(keystore);
      return true;
    }
  }

  establishedGroupEpochs.set(epochKey, true);
  keystore.establishedEpochs = keystore.establishedEpochs || {};
  keystore.establishedEpochs[epochKey] = true;
  await persistKeystoreToStorage(keystore);
  return true;
}

export function hasGroupSecret(channelId, cryptoEpoch = 1, matricule = null) {
  const ks = getActiveAgentKeystore(matricule);
  if (!ks) return false;
  const epochKey = `${ks.matricule}:${Number(channelId)}:${Number(cryptoEpoch || 1)}`;
  return Boolean(establishedGroupEpochs.get(epochKey) || ks.establishedEpochs?.[epochKey]);
}

export function clearGroupSecrets() {
  establishedGroupEpochs.clear();
  for (const ks of inMemoryKeystores.values()) {
    if (ks.establishedEpochs) {
      ks.establishedEpochs = {};
    }
  }
}

// ============================================================================
// 3. Chiffrement et Déchiffrement E2EE des Messages (Signal Pair-à-Pair)
// ============================================================================

async function computeParticipantSlotHash(prefix, channelId, cryptoEpoch, matricule) {
  const raw = new TextEncoder().encode(`${prefix}:CH_${channelId}:EP_${cryptoEpoch}:${matricule}`);
  const digest = await window.crypto.subtle.digest('SHA-256', raw);
  return bytesToBase64(new Uint8Array(digest).slice(0, 16));
}

/**
 * Chiffre un message (direct ou de groupe) avec le protocole Signal (`libsignal`).
 * Le message bourré (multiple de 256 octets) est chiffré séparément pour chaque
 * membre actif autorisé du canal via sa session Signal (`SessionBuilder` X3DH +
 * `SessionCipher` Double Ratchet).
 */
export async function encryptE2EEMessagePayload({
  channelId,
  cryptoEpoch = 1,
  plaintextObject,
  keystore,
  activeMembers = null,
}) {
  if (!keystore || !keystore.signalIdentityKeyPair) {
    throw new Error('Trousseau Signal non initialisé.');
  }

  const resolvedMembers =
    (Array.isArray(activeMembers) && activeMembers.length > 0
      ? activeMembers
      : channelActiveMembersCache.get(`${Number(channelId)}:${Number(cryptoEpoch)}`) ||
        channelActiveMembersCache.get(`${Number(channelId)}:latest`)) || [];

  const authorizedMembers = resolvedMembers.filter((m) => m && m.matricule && !m.is_revoked);
  if (authorizedMembers.length === 0) {
    throw new Error(
      'Aucun destinataire actif autorisé fourni pour établir les sessions Signal du canal.'
    );
  }

  const localStore = getOrHydrateSignalStore(keystore);
  const nonceBytes = window.crypto.getRandomValues(new Uint8Array(12));
  const nonceB64 = bytesToBase64(nonceBytes);

  const enrichedPlaintext = {
    ...plaintextObject,
    _meta: {
      channelId: Number(channelId),
      cryptoEpoch: Number(cryptoEpoch),
      senderMatricule: keystore.matricule,
      senderKeyFingerprint: keystore.keyFingerprint,
      nonceB64,
      clientTimestamp: new Date().toISOString(),
    },
  };

  const paddedBytes = padPlaintextObjectTo256Bytes(enrichedPlaintext);
  const senderSlot = await computeParticipantSlotHash(
    'SIGNAL_SENDER',
    channelId,
    cryptoEpoch,
    keystore.matricule
  );

  const recipientsMap = {};
  const ensureSelfIncluded = authorizedMembers.some((m) => m.matricule === keystore.matricule)
    ? authorizedMembers
    : [
        ...authorizedMembers,
        {
          matricule: keystore.matricule,
          e2ee_signing_public_key: JSON.stringify(keystore.signingPublicJwk),
        },
      ];

  for (const member of ensureSelfIncluded) {
    const recipientSlot = await computeParticipantSlotHash(
      'SIGNAL_RECIPIENT',
      channelId,
      cryptoEpoch,
      member.matricule
    );

    if (member.matricule === keystore.matricule) {
      const selfAddress = new SignalProtocolAddress(`${keystore.matricule}__SELF`, 2);
      const selfCiphertext = await encryptBytesWithSignalSession(
        localStore,
        selfAddress,
        paddedBytes,
        () => buildSelfDeviceBundle(keystore)
      );
      recipientsMap[recipientSlot] = {
        type: selfCiphertext.type,
        bodyB64: selfCiphertext.bodyB64,
        registrationId: selfCiphertext.registrationId,
        senderSlot,
        isSelfArchive: true,
      };
    } else {
      if (!member.e2ee_one_time_prekeys_json) {
        const existingSess = await localStore.loadSession(
          new SignalProtocolAddress(member.matricule, 1).toString()
        );
        if (!existingSess) {
          continue;
        }
      }
      const remoteAddress = new SignalProtocolAddress(member.matricule, 1);
      const remoteCiphertext = await encryptBytesWithSignalSession(
        localStore,
        remoteAddress,
        paddedBytes,
        () => extractMemberSignalPreKeyBundle(member)
      );
      recipientsMap[recipientSlot] = {
        type: remoteCiphertext.type,
        bodyB64: remoteCiphertext.bodyB64,
        registrationId: remoteCiphertext.registrationId,
        senderSlot,
      };
    }
  }

  const multiRecipientPayloadJson = JSON.stringify({
    v: 'SIGNAL_PAIRWISE_ENVELOPE_V1',
    protocol: E2EE_PROTOCOL_IDENTIFIER,
    channelId: Number(channelId),
    epoch: Number(cryptoEpoch),
    senderSlot,
    recipients: recipientsMap,
  });
  const ciphertextB64 = bytesToBase64(new TextEncoder().encode(multiRecipientPayloadJson));

  // Signature ECDSA P-256 de l'enveloppe multi-destinataires Signal (format Hex attendu par le serveur)
  const signingKey = await window.crypto.subtle.importKey(
    'jwk',
    keystore.signingPrivateJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );

  const signedData = new TextEncoder().encode(
    `${channelId}:${cryptoEpoch}:${nonceB64}:${ciphertextB64}`
  );
  const signatureBuffer = await window.crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    signingKey,
    signedData
  );
  const signatureHex = bytesToHex(new Uint8Array(signatureBuffer));

  await syncAndPersistSignalStore(localStore, keystore);

  return {
    channel_id: Number(channelId),
    crypto_epoch: Number(cryptoEpoch),
    ciphertext_payload: ciphertextB64,
    nonce_or_iv: nonceB64,
    authenticity_mac: signatureHex,
    e2ee_protocol: E2EE_PROTOCOL_IDENTIFIER,
  };
}

/**
 * Déchiffre et vérifie l'authenticité d'une enveloppe Signal (`libsignal`).
 * Rejette explicitement toute enveloppe utilisant l'ancien protocole WebCrypto
 * ou un protocole inconnu (protection anti-downgrade).
 */
export async function decryptE2EEMessagePayload(envelope, activeMembers = [], myKeystore = null) {
  try {
    // 1. Contrôle strict anti-downgrade du protocole E2EE
    if (!envelope || envelope.e2ee_protocol !== E2EE_PROTOCOL_IDENTIFIER) {
      const rejectedProto = envelope?.e2ee_protocol || 'INCONNU';
      return {
        decryptedOk: false,
        signatureVerified: false,
        isLegacyUnsupported: true,
        senderLabel: 'Protocole obsolète ou non autorisé',
        content: {
          text: `[Ancien message ou protocole non pris en charge (${rejectedProto}) — Déchiffrement refusé (Anti-Downgrade Signal)]`,
          type: 'text',
        },
      };
    }

    const keystore = myKeystore || getActiveAgentKeystore();
    if (!keystore || !keystore.signalIdentityKeyPair) {
      return {
        decryptedOk: false,
        signatureVerified: false,
        senderLabel: 'Trousseau Signal verrouillé',
        content: {
          text: '[Trousseau cryptographique Signal non initialisé]',
          type: 'text',
        },
      };
    }

    // 2. Décodage de l'enveloppe multi-destinataires Signal
    let outerPayload;
    try {
      const rawJson = new TextDecoder().decode(base64ToBytes(envelope.ciphertext_payload));
      outerPayload = JSON.parse(rawJson);
    } catch {
      return {
        decryptedOk: false,
        signatureVerified: false,
        isLegacyUnsupported: true,
        senderLabel: 'Format d’enveloppe incompatible',
        content: {
          text: '[Format de message antérieur non compatible avec les sessions Signal pair-à-pair]',
          type: 'text',
        },
      };
    }

    if (
      !outerPayload ||
      outerPayload.v !== 'SIGNAL_PAIRWISE_ENVELOPE_V1' ||
      outerPayload.protocol !== E2EE_PROTOCOL_IDENTIFIER ||
      Number(outerPayload.epoch) !== Number(envelope.crypto_epoch) ||
      Number(outerPayload.channelId) !== Number(envelope.channel_id)
    ) {
      return {
        decryptedOk: false,
        signatureVerified: false,
        isLegacyUnsupported: true,
        senderLabel: 'Enveloppe invalide ou époque falsifiée',
        content: {
          text: '[Enveloppe cryptographique rejetée : version ou époque Signal incohérente]',
          type: 'text',
        },
      };
    }

    // 3. Recherche de l'enveloppe Signal destinée à cet agent
    const myRecipientSlot = await computeParticipantSlotHash(
      'SIGNAL_RECIPIENT',
      envelope.channel_id,
      envelope.crypto_epoch,
      keystore.matricule
    );
    const mySignalEnvelope = outerPayload.recipients?.[myRecipientSlot];
    if (!mySignalEnvelope || !mySignalEnvelope.bodyB64) {
      return {
        decryptedOk: false,
        signatureVerified: false,
        senderLabel: 'Accès refusé (Hors session Signal)',
        content: {
          text: `[Chiffré de bout en bout via Signal (Époque #${envelope.crypto_epoch}) — Aucune enveloppe destinée à cet agent]`,
          type: 'text',
        },
      };
    }

    // 4. Identification de l'émetteur et vérification de sa signature ECDSA P-256 contre l'annuaire
    const signedData = new TextEncoder().encode(
      `${envelope.channel_id}:${envelope.crypto_epoch}:${envelope.nonce_or_iv}:${envelope.ciphertext_payload}`
    );
    const sigBytes = /^[0-9a-fA-F]+$/.test(envelope.authenticity_mac)
      ? hexToBytes(envelope.authenticity_mac)
      : base64ToBytes(envelope.authenticity_mac);

    const candidateMembers = [
      ...activeMembers,
      ...(activeMembers.some((m) => m.matricule === keystore.matricule)
        ? []
        : [
            {
              matricule: keystore.matricule,
              full_name: keystore.matricule,
              e2ee_signing_public_key: JSON.stringify(keystore.signingPublicJwk),
            },
          ]),
    ];

    let verifiedSender = null;
    for (const member of candidateMembers) {
      const signingKeyData = member?.e2ee_signing_public_key || member?.e2ee_signing_public_key_b64;
      if (!signingKeyData) continue;
      const expectedSenderSlot = await computeParticipantSlotHash(
        'SIGNAL_SENDER',
        envelope.channel_id,
        envelope.crypto_epoch,
        member.matricule
      );
      if (expectedSenderSlot !== outerPayload.senderSlot) continue;

      try {
        const pubKey = await importEcdsaPublicKeyFromMember(signingKeyData);
        const isValid = await window.crypto.subtle.verify(
          { name: 'ECDSA', hash: { name: 'SHA-256' } },
          pubKey,
          sigBytes,
          signedData
        );
        if (isValid) {
          verifiedSender = member;
          break;
        }
      } catch {
        // Continue checking candidates
      }
    }

    if (!verifiedSender) {
      return {
        decryptedOk: false,
        signatureVerified: false,
        senderLabel: 'Signature émetteur invalide',
        content: {
          text: '[Alerte Sécurité : Signature ECDSA de l’enveloppe Signal invalide ou émetteur non reconnu]',
          type: 'text',
        },
      };
    }

    // 5. Consultation du coffre local des messages déjà ratchettés (pour re-rendu UI du même message)
    const vaultKey = `${envelope.channel_id}:${envelope.crypto_epoch}:${envelope.nonce_or_iv}:${envelope.authenticity_mac}:${myRecipientSlot}`;
    if (keystore.decryptedMessageVault && keystore.decryptedMessageVault[vaultKey]) {
      const cachedPlaintext = keystore.decryptedMessageVault[vaultKey];
      return {
        decryptedOk: true,
        signatureVerified: true,
        senderMatricule: verifiedSender.matricule,
        senderLabel: verifiedSender.full_name || verifiedSender.matricule,
        senderRole: verifiedSender.role || '',
        senderKeyFingerprint: cachedPlaintext?._meta?.senderKeyFingerprint || '',
        content: cachedPlaintext,
      };
    }

    // 6. Déchiffrement cryptographique via la session Signal (`SessionCipher` Double Ratchet)
    const localStore = getOrHydrateSignalStore(keystore);
    let decryptedPaddedBytes;
    if (mySignalEnvelope.isSelfArchive && verifiedSender.matricule === keystore.matricule) {
      const selfSenderAddress = new SignalProtocolAddress(keystore.matricule, 1);
      decryptedPaddedBytes = await decryptBytesWithSignalSession(
        localStore.selfDeviceStore,
        selfSenderAddress,
        mySignalEnvelope
      );
    } else {
      const remoteAddress = new SignalProtocolAddress(verifiedSender.matricule, 1);
      decryptedPaddedBytes = await decryptBytesWithSignalSession(
        localStore,
        remoteAddress,
        mySignalEnvelope
      );
    }

    const parsedPlaintext = unpadPlaintextObjectFrom256Bytes(decryptedPaddedBytes);

    if (
      !parsedPlaintext?._meta ||
      Number(parsedPlaintext._meta.channelId) !== Number(envelope.channel_id) ||
      Number(parsedPlaintext._meta.cryptoEpoch) !== Number(envelope.crypto_epoch) ||
      parsedPlaintext._meta.senderMatricule !== verifiedSender.matricule
    ) {
      throw new Error('Métadonnées internes Signal (_meta) incohérentes avec l’enveloppe signée.');
    }

    keystore.decryptedMessageVault = keystore.decryptedMessageVault || {};
    keystore.decryptedMessageVault[vaultKey] = parsedPlaintext;
    await syncAndPersistSignalStore(localStore, keystore);

    return {
      decryptedOk: true,
      signatureVerified: true,
      senderMatricule: verifiedSender.matricule,
      senderLabel: verifiedSender.full_name || verifiedSender.matricule,
      senderRole: verifiedSender.role || '',
      senderKeyFingerprint: parsedPlaintext._meta.senderKeyFingerprint || '',
      content: parsedPlaintext,
    };
  } catch (err) {
    return {
      decryptedOk: false,
      signatureVerified: false,
      senderLabel: 'Indéchiffrable (Verrouillage Signal)',
      errorDetail: err?.message || String(err),
      content: {
        text: `[Chiffré de bout en bout via Signal (Époque #${envelope?.crypto_epoch || '?'}) — Déchiffrement refusé : ${err?.message || 'Clé absente ou consommée'}]`,
        type: 'text',
      },
    };
  }
}

// ============================================================================
// 4. Chiffrement E2EE des Pièces Jointes et Notes Vocales
//    (Clé symétrique aléatoire AES-256-GCM distribuée via les sessions Signal)
// ============================================================================

/**
 * Chiffre un fichier binaire / note vocale côté client avec une clé symétrique
 * aléatoire fraîche (AES-256-GCM, 256 bits) et un IV aléatoire (96 bits), après
 * bourrage à un multiple de 4096 octets.
 * La clé `attachment_key_b64` n'est JAMAIS envoyée à `/api/blobs` : elle est
 * transmise exclusivement dans l'enveloppe de message chiffrée par Signal.
 */
export async function encryptBinaryAttachmentE2EE(dataUrlOrBase64) {
  const randomKeyBytes = window.crypto.getRandomValues(new Uint8Array(32));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const paddedBytes = padAttachmentTo4096Bytes(dataUrlOrBase64);

  const aesKey = await window.crypto.subtle.importKey(
    'raw',
    randomKeyBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const encryptedBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    paddedBytes
  );

  const cipherUint8 = new Uint8Array(encryptedBuffer);
  const sha256Buf = await window.crypto.subtle.digest('SHA-256', cipherUint8);

  return {
    ciphertext_b64: bytesToBase64(cipherUint8),
    iv_b64: bytesToBase64(iv),
    attachment_key_b64: bytesToBase64(randomKeyBytes),
    ciphertext_sha256_b64: bytesToBase64(new Uint8Array(sha256Buf)),
    padded_plaintext_bytes: paddedBytes.byteLength,
  };
}

/**
 * Déchiffre une pièce jointe / note vocale téléchargée depuis `/api/blobs/{id}`
 * à l'aide de la clé symétrique `attachmentKeyB64` reçue via la session Signal.
 */
export async function decryptBinaryAttachmentE2EE(ciphertextB64, ivB64, attachmentKeyB64) {
  if (!attachmentKeyB64 || typeof attachmentKeyB64 !== 'string') {
    throw new Error(
      'Clé symétrique de pièce jointe absente : elle doit provenir d’une enveloppe Signal déchiffrée.'
    );
  }
  const keyBytes = base64ToBytes(attachmentKeyB64);
  if (keyBytes.byteLength !== 32) {
    throw new Error('Clé symétrique de pièce jointe invalide (256 bits requis).');
  }

  const aesKey = await window.crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const cipherBytes = base64ToBytes(ciphertextB64);
  const ivBytes = base64ToBytes(ivB64);
  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBytes },
    aesKey,
    cipherBytes
  );
  return unpadAttachmentFrom4096Bytes(decryptedBuffer);
}

// ============================================================================
// 5. Signature Cryptographique de Reçu de Lecture Probant (ECDSA P-256)
// ============================================================================

export async function signProbativeReadReceipt({
  messageId,
  ciphertextPayload,
  matricule,
  keystore,
}) {
  const signingKey = await window.crypto.subtle.importKey(
    'jwk',
    keystore.signingPrivateJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );

  const agentMatricule = matricule || keystore.matricule;
  const preimage = new TextEncoder().encode(
    `PROBATIVE_RECEIPT::MSG=${messageId}::AGENT=${agentMatricule}::CIPHER=${ciphertextPayload}`
  );
  const digestBuf = await window.crypto.subtle.digest('SHA-256', preimage);
  const signedPayloadHashHex = bytesToHex(new Uint8Array(digestBuf));

  const sigBuf = await window.crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    signingKey,
    new Uint8Array(digestBuf)
  );
  return {
    signature_hex: bytesToHex(new Uint8Array(sigBuf)),
    signed_payload_hash: signedPayloadHashHex,
  };
}

// ============================================================================
// 6. Simulation de rechargement navigateur & Effacement d'urgence (Remote Wipe)
// ============================================================================

export function clearInMemoryCryptoCaches() {
  inMemoryKeystores.clear();
  activeSignalStores.clear();
  establishedGroupEpochs.clear();
  try {
    if (window.sessionStorage) {
      const ssKeys = [];
      for (let i = 0; i < window.sessionStorage.length; i += 1) {
        const key = window.sessionStorage.key(i);
        if (key && key.startsWith(SESSION_KEYSTORE_CACHE_PREFIX)) {
          ssKeys.push(key);
        }
      }
      ssKeys.forEach((k) => window.sessionStorage.removeItem(k));
    }
  } catch {
    // ignore
  }
}

export function wipeLocalCryptoKeystore() {
  inMemoryWrappingKeys.clear();
  inMemoryKeystores.clear();
  activeSignalStores.clear();
  establishedGroupEpochs.clear();
  channelActiveMembersCache.clear();

  const lsKeysToRemove = [];
  for (let i = 0; i < window.localStorage.length; i += 1) {
    const key = window.localStorage.key(i);
    if (
      key &&
      (key.startsWith(WRAPPED_KEYSTORE_STORAGE_PREFIX) ||
        key.startsWith(LEGACY_KEYSTORE_STORAGE_PREFIX) ||
        key.startsWith('faso_secur_'))
    ) {
      lsKeysToRemove.push(key);
    }
  }
  lsKeysToRemove.forEach((k) => window.localStorage.removeItem(k));

  if (window.sessionStorage) {
    const ssKeysToRemove = [];
    for (let i = 0; i < window.sessionStorage.length; i += 1) {
      const key = window.sessionStorage.key(i);
      if (key && key.startsWith('faso_secur_')) {
        ssKeysToRemove.push(key);
      }
    }
    ssKeysToRemove.forEach((k) => window.sessionStorage.removeItem(k));
  }

  if (typeof window !== 'undefined' && window.indexedDB) {
    try {
      window.indexedDB.deleteDatabase(IDB_DATABASE_NAME);
    } catch {
      // ignore
    }
  }
}
