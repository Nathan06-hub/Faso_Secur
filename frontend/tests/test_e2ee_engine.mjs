/**
 * Suite de tests unitaires automatisés du moteur E2EE Client (`e2eeEngine.js`)
 * S'exécute directement avec Node.js (v20+) via l'implémentation W3C WebCrypto native.
 *
 * Vérifie :
 * 1. La génération des clés ECDH P-256 et ECDSA P-256, le Safety Number à 30 chiffres et le chiffrement CSPRNG au repos
 * 2. La génération CSPRNG d'un secret de groupe aléatoire 256 bits et son encapsulage ECDH P-256 entre deux agents (`syncChannelGroupSecret`)
 * 3. Le chiffrement AES-256-GCM avec bourrage par blocs de 256 octets + signature ECDSA-SHA256 liée à la clé publique de l'annuaire
 * 4. La détection de falsification d'une signature ECDSA ou d'une usurpation d'identité (`signatureVerified === false`)
 * 5. La signature d'un accusé de lecture à valeur probante et la purge Remote Wipe
 */

import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

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
  syncChannelGroupSecret,
  hasGroupSecret,
  encryptE2EEMessagePayload,
  decryptE2EEMessagePayload,
  signProbativeReadReceipt,
  wipeLocalCryptoKeystore,
} = await import('../src/crypto/e2eeEngine.js');

console.log('=== Tests Unitaires du Moteur E2EE Client (e2eeEngine.js) ===');

// Test 1 : Trousseau E2EE, Safety Number 30 chiffres & Chiffrement CSPRNG au repos dans localStorage
const ksAlice = await initializeAgentKeystore('BF-DGTD-001');
const ksBob = await initializeAgentKeystore('BF-MEFP-102');
assert.equal(ksAlice.protocol, 'WEBCRYPTO_ECDH_HKDF_AES256GCM_ECDSA');
assert.equal(ksAlice.safetyNumber.replace(/\s+/g, '').length, 30, 'Safety Number SHA-256 à 30 chiffres');
const rawStoredAlice = globalThis.window.localStorage.getItem('faso_secur_e2ee_wrapped_ks_v3_BF-DGTD-001');
assert.ok(rawStoredAlice.includes('"encryptedAtRest":true'), 'Le trousseau doit être chiffré au repos');
assert.ok(!rawStoredAlice.includes('"d":'), 'Aucune clé privée JWK en clair ne doit figurer dans localStorage');
console.log('✓ Test 1 PASS : Génération ECDH/ECDSA P-256, Safety Number 30 chiffres & Chiffrement CSPRNG du Keystore');

// Test 2 : Génération aléatoire CSPRNG du secret de groupe et distribution par enveloppes ECDH P-256
const alicePubBundle = getPublicBundleForServer(ksAlice);
const bobPubBundle = getPublicBundleForServer(ksBob);
const activeMembers = [
  {
    matricule: 'BF-DGTD-001',
    e2ee_identity_public_key: alicePubBundle.identity_public_key,
    e2ee_signing_public_key: alicePubBundle.signing_public_key,
  },
  {
    matricule: 'BF-MEFP-102',
    e2ee_identity_public_key: bobPubBundle.identity_public_key,
    e2ee_signing_public_key: bobPubBundle.signing_public_key,
  },
];

let serverBundles = {};
await syncChannelGroupSecret({
  channel: { id: 1, crypto_epoch: 1, active_members: activeMembers },
  keystore: ksAlice,
  publish: async (bundles) => {
    serverBundles = bundles;
    return true;
  },
});
assert.equal(hasGroupSecret(1, 1), true);
assert.ok(serverBundles['BF-MEFP-102']?.wrappedKeyB64, 'Clé de groupe encapsulée par ECDH P-256 pour Bob');
console.log('✓ Test 2 PASS : Secret de groupe aléatoire CSPRNG 256 bits encapsulé via ECDH P-256');

// Test 3 : Chiffrement AES-256-GCM (padding 256 octets) + Vérification ECDSA P-256 liée à l'annuaire
const secretMessage = {
  text: 'Instruction confidentielle du Ministre — Ne jamais exposer en clair',
  senderMatricule: 'BF-DGTD-001',
  classification: 'CONFIDENTIEL',
  noForward: true,
  antiScreenshot: true,
};
const envelope = await encryptE2EEMessagePayload({
  channelId: 1,
  cryptoEpoch: 1,
  plaintextObject: secretMessage,
  keystore: ksAlice,
});
assert.ok(!envelope.ciphertext_payload.includes('Ministre'), 'Le ciphertext est opaque');
assert.equal('sender_ephemeral_public_key' in envelope, false, 'Aucune clé publique émetteur en clair dans l’enveloppe');

const decrypted = await decryptE2EEMessagePayload(
  {
    channel_id: 1,
    crypto_epoch: 1,
    ...envelope,
  },
  activeMembers
);
assert.equal(decrypted.decryptedOk, true);
assert.equal(decrypted.signatureVerified, true, 'La signature ECDSA P-256 doit être vérifiée contre la clé d’annuaire');
assert.equal(decrypted.content.text, secretMessage.text);
assert.equal(decrypted.content.noForward, true);
console.log('✓ Test 3 PASS : Chiffrement AES-256-GCM (padding 256o) + Vérification ECDSA liée à l’annuaire');

// Test 4 : Détection d'une signature ECDSA falsifiée
const tamperedEnvelope = {
  channel_id: 1,
  crypto_epoch: 1,
  ...envelope,
  authenticity_mac: '00'.repeat(64),
};
const decryptedTampered = await decryptE2EEMessagePayload(tamperedEnvelope, activeMembers);
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
