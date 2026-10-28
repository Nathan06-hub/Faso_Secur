/**
 * Suite de tests unitaires automatisés du moteur E2EE Client (`e2eeEngine.js`)
 * S'exécute directement avec Node.js (v20+) via l'implémentation W3C WebCrypto native.
 *
 * Vérifie :
 * 1. La génération des clés ECDH P-256 et ECDSA P-256 et le chiffrement au repos dans localStorage
 * 2. L'accord de clé Diffie-Hellman (X3DH / ECDH P-256) entre deux agents et l'encapsulage de clé de groupe
 * 3. Le chiffrement AES-256-GCM + signature ECDSA-SHA256 et la vérification de signature au déchiffrement
 * 4. La détection de falsification d'une signature ECDSA (`signatureVerified === false`)
 * 5. La signature d'un accusé de lecture à valeur probante
 */

import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

// Polyfill minimal de l'environnement navigateur (`window.crypto`, `localStorage`, `sessionStorage`, `btoa`, `atob`)
class MemoryStorage {
  constructor() {
    this.store = new Map();
  }
  get length() {
    return this.store.size;
  }
  key(i) {
    return Array.from(this.store.keys())[i] || null;
  }
  getItem(k) {
    return this.store.has(k) ? this.store.get(k) : null;
  }
  setItem(k, v) {
    this.store.set(k, String(v));
  }
  removeItem(k) {
    this.store.delete(k);
  }
  clear() {
    this.store.clear();
  }
}

globalThis.window = {
  crypto: webcrypto,
  localStorage: new MemoryStorage(),
  sessionStorage: new MemoryStorage(),
  btoa: (str) => Buffer.from(str, 'binary').toString('base64'),
  atob: (b64) => Buffer.from(b64, 'base64').toString('binary'),
};

const {
  initializeAgentKeystore,
  getPublicBundleForServer,
  buildECDHWrappedGroupSessionBundles,
  encryptE2EEMessagePayload,
  decryptE2EEMessagePayload,
  signProbativeReadReceipt,
  wipeLocalCryptoKeystore,
} = await import('../src/crypto/e2eeEngine.js');

console.log('=== Tests Unitaires du Moteur E2EE Client (e2eeEngine.js) ===');

// Test 1 : Trousseau E2EE & Chiffrement au repos dans localStorage
const ksAlice = await initializeAgentKeystore('BF-DGTD-001');
const ksBob = await initializeAgentKeystore('BF-MEFP-102');
assert.equal(ksAlice.protocol, 'MATRIX_OLM_MEGOLM_X3DH_V2');
const rawStoredAlice = globalThis.window.localStorage.getItem('faso_secur_e2ee_wrapped_ks_v2_BF-DGTD-001');
assert.ok(rawStoredAlice.includes('"encryptedAtRest":true'), 'Le trousseau doit être chiffré au repos');
assert.ok(!rawStoredAlice.includes('"d":'), 'Aucune clé privée JWK en clair ne doit figurer dans localStorage');
console.log('✓ Test 1 PASS : Génération ECDH/ECDSA P-256 & Chiffrement au repos du Keystore');

// Test 2 : Accord de clé Diffie-Hellman (X3DH / ECDH P-256) entre Alice et Bob
const bobPubBundle = getPublicBundleForServer(ksBob);
const wrappedBundles = await buildECDHWrappedGroupSessionBundles({
  channelId: 1,
  cryptoEpoch: 1,
  activeMembers: [
    {
      matricule: 'BF-MEFP-102',
      e2ee_identity_public_key: bobPubBundle.identity_public_key,
    },
  ],
  keystore: ksAlice,
});
assert.ok(wrappedBundles['BF-MEFP-102']?.wrappedKeyB64, 'Clé de groupe encapsulée par ECDH P-256 pour Bob');
console.log('✓ Test 2 PASS : Accord Diffie-Hellman X3DH / ECDH P-256 et encapsulage de clé Megolm');

// Test 3 : Chiffrement AES-256-GCM + Signature ECDSA-SHA256 & Vérification à la réception
const secretMessage = {
  text: 'Instruction confidentielle du Ministre — Ne jamais exposer en clair',
  senderMatricule: 'BF-DGTD-001',
  classification: 'CONFIDENTIEL',
};
const envelope = await encryptE2EEMessagePayload({
  channelId: 1,
  cryptoEpoch: 1,
  plaintextObject: secretMessage,
  keystore: ksAlice,
});
assert.ok(!envelope.ciphertext_payload.includes('Ministre'), 'Le ciphertext est opaque');

const decrypted = await decryptE2EEMessagePayload({
  channel_id: 1,
  crypto_epoch: 1,
  ...envelope,
});
assert.equal(decrypted.decryptedOk, true);
assert.equal(decrypted.signatureVerified, true, 'La signature ECDSA P-256 doit être vérifiée côté client');
assert.equal(decrypted.content.text, secretMessage.text);
console.log('✓ Test 3 PASS : Chiffrement AES-256-GCM + Vérification de signature ECDSA P-256 côté client');

// Test 4 : Détection d'une signature ECDSA falsifiée
const tamperedEnvelope = {
  channel_id: 1,
  crypto_epoch: 1,
  ...envelope,
  authenticity_mac: '00'.repeat(64),
};
const decryptedTampered = await decryptE2EEMessagePayload(tamperedEnvelope);
assert.equal(decryptedTampered.signatureVerified, false, 'Une signature falsifiée doit être détectée');
console.log('✓ Test 4 PASS : Rejet d’une signature ECDSA falsifiée');

// Test 5 : Signature d'un accusé de lecture à valeur probante & Purge Remote Wipe
const receipt = await signProbativeReadReceipt({
  messageId: 42,
  ciphertextPayload: envelope.ciphertext_payload,
  matricule: 'BF-MEFP-102',
  keystore: ksBob,
});
assert.equal(receipt.signature_hex.length, 128);
wipeLocalCryptoKeystore();
assert.equal(globalThis.window.localStorage.length, 0, 'Le Remote Wipe doit vider intégralement le Keystore');
console.log('✓ Test 5 PASS : Accusé probant ECDSA & Purge Remote Wipe');
console.log('=== 5/5 TESTS UNITAIRES E2EE CLIENT RÉUSSIS ===');
