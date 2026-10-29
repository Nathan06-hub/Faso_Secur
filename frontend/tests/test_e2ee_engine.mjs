/**
 * ============================================================================
 * Suite de tests automatisés du moteur E2EE Client (`e2eeEngine.js`)
 * S'exécute directement avec Node.js via `@privacyresearch/libsignal-protocol-typescript`
 * et l'API W3C WebCrypto native.
 *
 * Couvre l'intégralité des exigences de vérification :
 * 1. Échange chiffré Signal entre 2 membres (1-à-1) et dans un groupe de 3 membres (Alice, Bob, Charlie)
 * 2. Échec de déchiffrement pour un destinataire non autorisé (Mallory / hors canal)
 * 3. Révocation d'un membre (Charlie) et impossibilité de déchiffrer les nouveaux messages post-révocation
 * 4. Rechargement du navigateur (purge RAM + sessionStorage) avec restauration des clés et des sessions Signal Double Ratchet actives
 * 5. Consommation effective et non-réutilisation des pré-clés à usage unique (One-Time PreKeys X3DH)
 * 6. Chiffrement d'une pièce jointe avec clé symétrique aléatoire, distribution de la clé via Signal et déchiffrement
 * 7. Rejet strict d'une enveloppe utilisant l'ancien protocole (`WEBCRYPTO_ECDH_HKDF_AES256GCM_ECDSA`) ou un protocole inconnu
 * 8. Absence de contenu lisible en clair dans les enveloppes et payloads sérialisés
 * 9. Signature d'accusé de lecture probant ECDSA P-256 et effacement d'urgence (Remote Wipe)
 * ============================================================================
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

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}

globalThis.window = {
  crypto: webcrypto,
  localStorage: new MemoryStorage(),
  sessionStorage: new MemoryStorage(),
  btoa: (str) => Buffer.from(str, 'binary').toString('base64'),
  atob: (b64) => Buffer.from(b64, 'base64').toString('binary'),
};

const {
  E2EE_PROTOCOL_IDENTIFIER,
  LEGACY_UNSUPPORTED_PROTOCOL_IDENTIFIER,
  initializeAgentKeystore,
  getPublicBundleForServer,
  createSignalStoreFromKeystore,
  establishSignalDirectSession,
  encryptSignalDirectMessage,
  decryptSignalDirectMessage,
  syncChannelGroupSecret,
  hasGroupSecret,
  clearGroupSecrets,
  clearInMemoryCryptoCaches,
  encryptE2EEMessagePayload,
  decryptE2EEMessagePayload,
  encryptBinaryAttachmentE2EE,
  decryptBinaryAttachmentE2EE,
  signProbativeReadReceipt,
  wipeLocalCryptoKeystore,
  base64ToBytes,
} = await import('../src/crypto/e2eeEngine.js');

console.log('=== Suite de Tests E2EE Client (Signal X3DH + Double Ratchet Pair-à-Pair) ===');

// ----------------------------------------------------------------------------
// Test 1 : Initialisation des trousseaux Signal (Alice, Bob, Charlie, Mallory)
//          & Chiffrement au repos dans localStorage
// ----------------------------------------------------------------------------
const ksAlice = await initializeAgentKeystore('BF-DGTD-001');
const ksBob = await initializeAgentKeystore('BF-MEFP-102');
const ksCharlie = await initializeAgentKeystore('BF-MDAC-205');
const ksMallory = await initializeAgentKeystore('BF-INTRUS-999');

assert.equal(ksAlice.protocol, E2EE_PROTOCOL_IDENTIFIER);
assert.equal(ksAlice.signalPreKeys.length, 20, '20 One-Time PreKeys générées à l’initialisation');
assert.equal(ksAlice.safetyNumber.replace(/\s+/g, '').length, 30, 'Safety Number SHA-256 à 30 chiffres');

const rawStoredAlice = globalThis.window.localStorage.getItem('faso_secur_e2ee_wrapped_ks_v3_BF-DGTD-001');
assert.ok(rawStoredAlice.includes('"encryptedAtRest":true'), 'Le trousseau est chiffré au repos');
assert.ok(!rawStoredAlice.includes('"d":'), 'Aucune clé privée JWK en clair dans localStorage');
assert.ok(!rawStoredAlice.includes(ksAlice.signalIdentityPrivateB64), 'Aucune clé privée Signal en clair dans localStorage');

function buildMemberDirectoryEntry(ks, fullName, role = 'AGENT_PUBLIC') {
  const pub = getPublicBundleForServer(ks);
  return {
    matricule: ks.matricule,
    full_name: fullName,
    role,
    is_revoked: false,
    e2ee_identity_public_key: pub.identity_public_key,
    e2ee_signing_public_key: pub.signing_public_key,
    e2ee_signed_prekey_public: pub.signed_prekey_public,
    e2ee_one_time_prekeys_json: pub.one_time_prekeys_json,
  };
}

const groupMembersEpoch1 = [
  buildMemberDirectoryEntry(ksAlice, 'Alice Ouédraogo', 'ADMIN_DGTD'),
  buildMemberDirectoryEntry(ksBob, 'Bob Kaboré', 'AGENT_PUBLIC'),
  buildMemberDirectoryEntry(ksCharlie, 'Charlie Sawadogo', 'AGENT_PUBLIC'),
];

console.log('✓ Test 1 PASS : Génération des clés Signal (20 One-Time PreKeys) & Chiffrement au repos vérifiés');

// ----------------------------------------------------------------------------
// Test 2 : Échange chiffré entre 2 membres (1-à-1) ET dans un groupe de 3 membres
//          via les sessions Signal pair-à-pair + Absence de clair dans les trames
// ----------------------------------------------------------------------------
// 2a. Échange direct 1-à-1 entre Alice et Bob
const aliceStore = createSignalStoreFromKeystore(ksAlice);
const bobStore = createSignalStoreFromKeystore(ksBob);
await establishSignalDirectSession(aliceStore, 'BF-MEFP-102', groupMembersEpoch1[1]);

const directMsg1 = await encryptSignalDirectMessage({
  localStore: aliceStore,
  remoteMatricule: 'BF-MEFP-102',
  plaintextObject: { text: 'Message direct 1-à-1 X3DH Alice -> Bob', senderMatricule: 'BF-DGTD-001' },
  keystore: ksAlice,
});
assert.equal(directMsg1.signal_message_type, 3, '1er message direct = PreKeyWhisperMessage (type 3)');

const decDirect1 = await decryptSignalDirectMessage({
  localStore: bobStore,
  senderMatricule: 'BF-DGTD-001',
  recipientMatricule: 'BF-MEFP-102',
  envelope: directMsg1,
  senderSigningPublicJwk: ksAlice.signingPublicJwk,
});
assert.equal(decDirect1.decryptedOk, true);
assert.equal(decDirect1.content.text, 'Message direct 1-à-1 X3DH Alice -> Bob');

const directReply = await encryptSignalDirectMessage({
  localStore: bobStore,
  remoteMatricule: 'BF-DGTD-001',
  plaintextObject: { text: 'Réponse directe Double Ratchet Bob -> Alice', senderMatricule: 'BF-MEFP-102' },
  keystore: ksBob,
});
assert.equal(directReply.signal_message_type, 1, 'Réponse sur session établie = WhisperMessage (type 1)');

const decDirectReply = await decryptSignalDirectMessage({
  localStore: aliceStore,
  senderMatricule: 'BF-MEFP-102',
  recipientMatricule: 'BF-DGTD-001',
  envelope: directReply,
  senderSigningPublicJwk: ksBob.signingPublicJwk,
});
assert.equal(decDirectReply.decryptedOk, true);
assert.equal(decDirectReply.content.text, 'Réponse directe Double Ratchet Bob -> Alice');

// 2b. Échange de groupe à 3 membres (Alice, Bob, Charlie) via enveloppes Signal pair-à-pair
const groupSecretText = 'Synthèse interministérielle confidentielle — Groupe 3 membres';
const groupEnvelope1 = await encryptE2EEMessagePayload({
  channelId: 10,
  cryptoEpoch: 1,
  plaintextObject: {
    text: groupSecretText,
    classification: 'CONFIDENTIEL',
    noForward: true,
    antiScreenshot: true,
  },
  keystore: ksAlice,
  activeMembers: groupMembersEpoch1,
});

assert.equal(groupEnvelope1.e2ee_protocol, E2EE_PROTOCOL_IDENTIFIER);
// Vérification de l'absence totale de texte ou matricule lisible dans le payload sérialisé
const decodedOuterStr = new TextDecoder().decode(base64ToBytes(groupEnvelope1.ciphertext_payload));
assert.ok(!groupEnvelope1.ciphertext_payload.includes('Synthèse'), 'Aucun texte clair dans ciphertext_payload');
assert.ok(!decodedOuterStr.includes('Synthèse'), 'Aucun texte clair dans le JSON externe');
assert.ok(!decodedOuterStr.includes('BF-DGTD-001'), 'Aucun matricule émetteur en clair dans le JSON externe');
assert.ok(!decodedOuterStr.includes('BF-MEFP-102'), 'Aucun matricule destinataire en clair dans le JSON externe');

const decGroupByAlice = await decryptE2EEMessagePayload(groupEnvelope1, groupMembersEpoch1, ksAlice);
const decGroupByBob = await decryptE2EEMessagePayload(groupEnvelope1, groupMembersEpoch1, ksBob);
const decGroupByCharlie = await decryptE2EEMessagePayload(groupEnvelope1, groupMembersEpoch1, ksCharlie);

assert.equal(decGroupByAlice.decryptedOk, true, 'Alice déchiffre sa propre copie Signal');
assert.equal(decGroupByBob.decryptedOk, true, 'Bob déchiffre son enveloppe Signal');
assert.equal(decGroupByCharlie.decryptedOk, true, 'Charlie déchiffre son enveloppe Signal');
assert.equal(decGroupByBob.content.text, groupSecretText);
assert.equal(decGroupByCharlie.content.text, groupSecretText);
assert.equal(decGroupByBob.signatureVerified, true);
assert.equal(decGroupByCharlie.signatureVerified, true);

console.log('✓ Test 2 PASS : Échange chiffré 1-à-1 et groupe à 3 membres via Signal + Opacité des trames vérifiés');

// ----------------------------------------------------------------------------
// Test 3 : Échec de déchiffrement pour un destinataire non autorisé (Mallory)
// ----------------------------------------------------------------------------
const decGroupByMallory = await decryptE2EEMessagePayload(groupEnvelope1, groupMembersEpoch1, ksMallory);
assert.equal(decGroupByMallory.decryptedOk, false, 'Mallory (non-membre) ne peut pas déchiffrer le message');
assert.equal(decGroupByMallory.signatureVerified, false);
assert.ok(!JSON.stringify(decGroupByMallory).includes(groupSecretText));

console.log('✓ Test 3 PASS : Échec de déchiffrement pour un destinataire non autorisé (Mallory)');

// ----------------------------------------------------------------------------
// Test 4 : Consommation et non-réutilisation des pré-clés à usage unique (One-Time PreKeys)
// ----------------------------------------------------------------------------
// Charlie avait 20 One-Time PreKeys avant de recevoir le PreKeyWhisperMessage d'Alice (groupEnvelope1).
// Après déchiffrement de groupEnvelope1, la pré-clé #1 de Charlie a été consommée et supprimée !
const charlieStore = createSignalStoreFromKeystore(ksCharlie);
const consumedPreKey1 = await charlieStore.loadPreKey(1);
assert.equal(consumedPreKey1, undefined, 'La One-Time PreKey #1 de Charlie doit être supprimée après consommation');
assert.equal(ksCharlie.signalPreKeys.length, 19, 'Il reste exactement 19 One-Time PreKeys dans le trousseau persisté de Charlie');

// Tentons de forcer Bob à établir une nouvelle session vers Charlie en réutilisant la One-Time PreKey #1 déjà consommée !
const staleCharlieMemberWithConsumedPreKey1 = {
  ...groupMembersEpoch1[2],
  e2ee_one_time_prekeys_json: JSON.stringify({
    protocol: E2EE_PROTOCOL_IDENTIFIER,
    signal_prekey_bundle: {
      registrationId: ksCharlie.signalRegistrationId,
      identityKeyB64: ksCharlie.signalIdentityKeyPair.pubKeyB64,
      signedPreKey: {
        keyId: ksCharlie.signalSignedPreKey.keyId,
        publicKeyB64: ksCharlie.signalSignedPreKey.pubKeyB64,
        signatureB64: ksCharlie.signalSignedPreKey.signatureB64,
      },
      preKey: {
        keyId: 1, // Pré-clé #1 DÉJÀ consommée par Alice !
        publicKeyB64: JSON.parse(groupMembersEpoch1[2].e2ee_one_time_prekeys_json).signal_prekey_bundle.signedPreKey.publicKeyB64,
      },
      oneTimePreKeys: [],
    },
  }),
};

const replayPreKeyEnvelopeFromBob = await encryptE2EEMessagePayload({
  channelId: 10,
  cryptoEpoch: 1,
  plaintextObject: { text: 'Tentative avec PreKey #1 déjà consommée' },
  keystore: ksBob,
  activeMembers: [groupMembersEpoch1[1], staleCharlieMemberWithConsumedPreKey1],
});

const decReusedPreKeyByCharlie = await decryptE2EEMessagePayload(
  replayPreKeyEnvelopeFromBob,
  groupMembersEpoch1,
  ksCharlie
);
assert.equal(
  decReusedPreKeyByCharlie.decryptedOk,
  false,
  'Charlie doit rejeter toute nouvelle session tentant de réutiliser la One-Time PreKey #1 déjà consommée'
);

console.log('✓ Test 4 PASS : Consommation effective et non-réutilisation des pré-clés à usage unique (One-Time PreKeys)');

// ----------------------------------------------------------------------------
// Test 5 : Révocation d'un membre (Charlie) et impossibilité de lire les nouveaux messages
// ----------------------------------------------------------------------------
const groupMembersEpoch2AfterCharlieRevoked = [
  buildMemberDirectoryEntry(ksAlice, 'Alice Ouédraogo', 'ADMIN_DGTD'),
  buildMemberDirectoryEntry(ksBob, 'Bob Kaboré', 'AGENT_PUBLIC'),
  { ...buildMemberDirectoryEntry(ksCharlie, 'Charlie Sawadogo', 'AGENT_PUBLIC'), is_revoked: true },
];

let rotatedBundlesEpoch2 = {};
await syncChannelGroupSecret({
  channel: {
    id: 10,
    crypto_epoch: 2,
    active_members: groupMembersEpoch2AfterCharlieRevoked.filter((m) => !m.is_revoked),
  },
  keystore: ksAlice,
  publish: async (bundles) => {
    rotatedBundlesEpoch2 = bundles;
    return true;
  },
});

assert.ok(rotatedBundlesEpoch2['BF-DGTD-001'], 'Alice reçoit le bundle d’époque 2');
assert.ok(rotatedBundlesEpoch2['BF-MEFP-102'], 'Bob reçoit le bundle d’époque 2');
assert.equal(
  'BF-MDAC-205' in rotatedBundlesEpoch2,
  false,
  'Charlie (révoqué) est exclu des bundles de la nouvelle époque 2'
);

const postRevocationText = 'Opération post-révocation — Strictement réservé aux membres restants (Époque 2)';
const groupEnvelopeEpoch2 = await encryptE2EEMessagePayload({
  channelId: 10,
  cryptoEpoch: 2,
  plaintextObject: { text: postRevocationText },
  keystore: ksAlice,
  activeMembers: groupMembersEpoch2AfterCharlieRevoked,
});

const decEpoch2ByBob = await decryptE2EEMessagePayload(
  groupEnvelopeEpoch2,
  groupMembersEpoch2AfterCharlieRevoked,
  ksBob
);
const decEpoch2ByCharlie = await decryptE2EEMessagePayload(
  groupEnvelopeEpoch2,
  groupMembersEpoch2AfterCharlieRevoked,
  ksCharlie
);

assert.equal(decEpoch2ByBob.decryptedOk, true, 'Bob (membre actif restant) déchiffre le message d’époque 2');
assert.equal(decEpoch2ByBob.content.text, postRevocationText);
assert.equal(decEpoch2ByCharlie.decryptedOk, false, 'Charlie (révoqué) est incapable de déchiffrer le message d’époque 2');
assert.ok(!JSON.stringify(decEpoch2ByCharlie).includes(postRevocationText));

console.log('✓ Test 5 PASS : Révocation d’un membre et impossibilité de lire les nouveaux messages post-révocation');

// ----------------------------------------------------------------------------
// Test 6 : Rechargement du navigateur (purge mémoire + sessionStorage) avec
//          restauration complète des clés ET des sessions Signal Double Ratchet
// ----------------------------------------------------------------------------
clearInMemoryCryptoCaches();
assert.equal(globalThis.window.sessionStorage.length, 0, 'sessionStorage vidé (simulation fermeture onglet)');

const ksAliceReloaded = await initializeAgentKeystore('BF-DGTD-001');
const ksBobReloaded = await initializeAgentKeystore('BF-MEFP-102');

assert.equal(ksAliceReloaded.safetyNumber, ksAlice.safetyNumber, 'Safety Number d’Alice préservé après rechargement');
assert.equal(ksBobReloaded.safetyNumber, ksBob.safetyNumber, 'Safety Number de Bob préservé après rechargement');

// Bob envoie un nouveau message à Alice APRÈS rechargement sans ré-exécuter X3DH :
// la session Signal restaurée depuis le trousseau chiffré doit produire un WhisperMessage (type 1) !
const activeAfterReload = [
  buildMemberDirectoryEntry(ksAliceReloaded, 'Alice Ouédraogo', 'ADMIN_DGTD'),
  buildMemberDirectoryEntry(ksBobReloaded, 'Bob Kaboré', 'AGENT_PUBLIC'),
];

const postReloadEnvelopeFromBob = await encryptE2EEMessagePayload({
  channelId: 10,
  cryptoEpoch: 2,
  plaintextObject: { text: 'Message envoyé par Bob après rechargement complet du navigateur' },
  keystore: ksBobReloaded,
  activeMembers: activeAfterReload,
});

// Vérifions que la session Bob -> Alice utilise bien le Double Ratchet restauré (type 1 WhisperMessage)
const parsedPostReloadOuter = JSON.parse(
  new TextDecoder().decode(base64ToBytes(postReloadEnvelopeFromBob.ciphertext_payload))
);
const recipientTypes = Object.values(parsedPostReloadOuter.recipients)
  .filter((r) => !r.isSelfArchive)
  .map((r) => r.type);
assert.deepEqual(
  recipientTypes,
  [1],
  'La session Signal restaurée après rechargement continue en WhisperMessage (type 1) sans réinitialiser X3DH'
);

const decPostReloadByAlice = await decryptE2EEMessagePayload(
  postReloadEnvelopeFromBob,
  activeAfterReload,
  ksAliceReloaded
);
assert.equal(decPostReloadByAlice.decryptedOk, true, 'Alice déchiffre le message post-rechargement avec sa session restaurée');
assert.equal(decPostReloadByAlice.content.text, 'Message envoyé par Bob après rechargement complet du navigateur');

console.log('✓ Test 6 PASS : Rechargement du navigateur avec restauration des clés et des sessions Signal Double Ratchet');

// ----------------------------------------------------------------------------
// Test 7 : Chiffrement d'une pièce jointe avec clé aléatoire, distribution de la
//          clé via les sessions Signal et déchiffrement par le destinataire
// ----------------------------------------------------------------------------
const sampleAttachmentDataUrl =
  'data:application/pdf;base64,JVBERi0xLjQKMSAwIG9iago8PCAvVHlwZSAvQ2F0YWxvZyA+PgplbmRvYmoK';
const encryptedAttachment = await encryptBinaryAttachmentE2EE(sampleAttachmentDataUrl);

assert.equal(encryptedAttachment.padded_plaintext_bytes % 4096, 0, 'Bourrage de la pièce jointe à 4096 octets');
assert.ok(encryptedAttachment.attachment_key_b64, 'Clé symétrique aléatoire générée pour la pièce jointe');
assert.ok(!encryptedAttachment.ciphertext_b64.includes('JVBERi0'), 'Le blob chiffré est opaque');

// Alice distribue la clé symétrique de la pièce jointe à Bob via leur session Signal
const attachmentMsgEnvelope = await encryptE2EEMessagePayload({
  channelId: 10,
  cryptoEpoch: 2,
  plaintextObject: {
    text: 'Rapport PDF chiffré',
    messageKind: 'ATTACHMENT',
    blobId: 'blob_test_001',
    attachmentKeyB64: encryptedAttachment.attachment_key_b64,
    attachmentIvB64: encryptedAttachment.iv_b64,
  },
  keystore: ksAliceReloaded,
  activeMembers: activeAfterReload,
});

const decAttachmentMsgByBob = await decryptE2EEMessagePayload(
  attachmentMsgEnvelope,
  activeAfterReload,
  ksBobReloaded
);
assert.equal(decAttachmentMsgByBob.decryptedOk, true);
const receivedAttachmentKeyB64 = decAttachmentMsgByBob.content.attachmentKeyB64;
assert.equal(receivedAttachmentKeyB64, encryptedAttachment.attachment_key_b64);

const decryptedAttachmentDataUrl = await decryptBinaryAttachmentE2EE(
  encryptedAttachment.ciphertext_b64,
  encryptedAttachment.iv_b64,
  receivedAttachmentKeyB64
);
assert.equal(decryptedAttachmentDataUrl, sampleAttachmentDataUrl, 'Pièce jointe déchiffrée et débourrée à l’identique');

// Vérifier que sans la clé issue de Signal, le déchiffrement de la pièce jointe échoue
await assert.rejects(
  async () => decryptBinaryAttachmentE2EE(encryptedAttachment.ciphertext_b64, encryptedAttachment.iv_b64, null),
  /Clé symétrique de pièce jointe absente/
);

console.log('✓ Test 7 PASS : Chiffrement de pièce jointe avec clé aléatoire, distribution via Signal et déchiffrement');

// ----------------------------------------------------------------------------
// Test 8 : Rejet d'une enveloppe utilisant l'ancien protocole ou un protocole inconnu
// ----------------------------------------------------------------------------
const downgradedEnvelope = {
  ...postReloadEnvelopeFromBob,
  e2ee_protocol: LEGACY_UNSUPPORTED_PROTOCOL_IDENTIFIER,
};
const decDowngraded = await decryptE2EEMessagePayload(downgradedEnvelope, activeAfterReload, ksAliceReloaded);
assert.equal(decDowngraded.decryptedOk, false, 'Une enveloppe avec l’ancien protocole doit être rejetée');
assert.equal(decDowngraded.isLegacyUnsupported, true, 'Identifiée explicitement comme protocole antérieur non pris en charge');

const unknownProtoEnvelope = {
  ...postReloadEnvelopeFromBob,
  e2ee_protocol: 'CUSTOM_HOMEMADE_CRYPTO_V0',
};
const decUnknownProto = await decryptE2EEMessagePayload(unknownProtoEnvelope, activeAfterReload, ksAliceReloaded);
assert.equal(decUnknownProto.decryptedOk, false, 'Un protocole inconnu doit être rejeté');
assert.equal(decUnknownProto.isLegacyUnsupported, true);

console.log('✓ Test 8 PASS : Rejet strict des enveloppes utilisant l’ancien protocole ou un protocole inconnu (Anti-Downgrade)');

// ----------------------------------------------------------------------------
// Test 9 : Signature d'accusé probant ECDSA P-256 & Effacement Remote Wipe
// ----------------------------------------------------------------------------
const receipt = await signProbativeReadReceipt({
  messageId: 77,
  ciphertextPayload: postReloadEnvelopeFromBob.ciphertext_payload,
  matricule: 'BF-MEFP-102',
  keystore: ksBobReloaded,
});
assert.equal(receipt.signature_hex.length, 128);
assert.equal(receipt.signed_payload_hash.length, 64);

wipeLocalCryptoKeystore();
assert.equal(globalThis.window.localStorage.length, 0, 'Le Remote Wipe vide intégralement localStorage');

console.log('✓ Test 9 PASS : Signature d’accusé probant ECDSA P-256 & Purge Remote Wipe');
console.log('=== 9/9 TESTS AUTOMATISÉS E2EE CLIENT (SIGNAL PAIR-À-PAIR + PIÈCES JOINTES + ANTI-DOWNGRADE) RÉUSSIS ===');
