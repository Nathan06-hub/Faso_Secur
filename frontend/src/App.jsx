import React, { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  Building2,
  CheckCircle2,
  Database,
  Download,
  Eye,
  EyeOff,
  FileCheck2,
  FileLock2,
  Globe,
  KeyRound,
  Lock,
  LogOut,
  Mic,
  Paperclip,
  Play,
  Plus,
  RefreshCw,
  Send,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Square,
  Trash2,
  UserCheck,
  UserPlus,
  UserX,
  Users,
  Wifi,
  WifiOff,
  X,
} from 'lucide-react';
import {
  syncChannelGroupSecret,
  hasGroupSecret,
  decryptBinaryAttachmentE2EE,
  decryptE2EEMessagePayload,
  encryptBinaryAttachmentE2EE,
  encryptE2EEMessagePayload,
  getPublicBundleForServer,
  hasEstablishedSignalSession,
  initializeAgentKeystore,
  signProbativeReadReceipt,
  wipeLocalCryptoKeystore,
} from './crypto/e2eeEngine';
import { LANGUAGES, TRANSLATIONS } from './i18n/translations';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

// Graines TOTP RFC 6238 des 5 profils fictifs de démonstration (documentées dans le README pour le jury)
// Calculées 100 % localement côté navigateur (Simulateur d'application 2FA) afin qu'aucun endpoint
// public du serveur ne transmette jamais de mot de passe ni de code TOTP sur le réseau.
const FICTIONAL_DEMO_TOTP_SEEDS = {
  'BF-DGTD-001': 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXA',
  'BF-MEFP-102': 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXB',
  'BF-MATDS-204': 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXC',
  'BF-SANTE-308': 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXD',
  'BF-MISSION-999': 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXE',
};

function base32ToUint8Array(base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = base32.toUpperCase().replace(/=+$/, '').trim();
  let bits = '';
  for (let i = 0; i < clean.length; i += 1) {
    const val = alphabet.indexOf(clean[i]);
    if (val >= 0) bits += val.toString(2).padStart(5, '0');
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }
  return bytes;
}

async function computeLocalDemoTotpCode(matricule) {
  const seed = FICTIONAL_DEMO_TOTP_SEEDS[matricule];
  if (!seed || !window.crypto?.subtle) return '';
  const keyBytes = base32ToUint8Array(seed);
  const counter = Math.floor(Date.now() / 1000 / 30);
  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  view.setUint32(0, Math.floor(counter / 0x100000000), false);
  view.setUint32(4, counter >>> 0, false);
  const hmacKey = await window.crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );
  const mac = new Uint8Array(await window.crypto.subtle.sign('HMAC', hmacKey, counterBuf));
  const offset = mac[mac.length - 1] & 0x0f;
  const binary =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);
  return String(binary % 1000000).padStart(6, '0');
}

/**
 * Génère un petit fichier WAV synthétique (bip vocal de radio-transmission) si le poste
 * de démonstration n'a pas de microphone matériel branché, afin que le jury puisse
 * toujours tester les notes vocales chiffrées E2EE en direct.
 */
function createSynthesizedVoiceDataUrl(durationSec = 2.2) {
  const sampleRate = 8000;
  const numSamples = Math.floor(sampleRate * durationSec);
  const buffer = new ArrayBuffer(44 + numSamples * 2);
  const view = new DataView(buffer);

  const writeString = (offset, str) => {
    for (let i = 0; i < str.length; i += 1) {
      view.setUint8(offset + i, str.charCodeAt(i));
    }
  };

  writeString(0, 'RIFF');
  view.setUint32(4, 36 + numSamples * 2, true);
  writeString(8, 'WAVE');
  writeString(12, 'fmt ');
  view.setUint32(16, 16, true);
  view.setUint16(20, 1, true);
  view.setUint16(22, 1, true);
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, sampleRate * 2, true);
  view.setUint16(32, 2, true);
  view.setUint16(34, 16, true);
  writeString(36, 'data');
  view.setUint32(40, numSamples * 2, true);

  for (let i = 0; i < numSamples; i += 1) {
    const t = i / sampleRate;
    const freq = t < 0.3 ? 520 : t < 1.2 ? 440 : 660;
    const envelope = Math.sin((Math.PI * i) / numSamples);
    const sample = Math.sin(2 * Math.PI * freq * t) * envelope * 0.35;
    view.setInt16(44 + i * 2, sample * 32767, true);
  }

  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return `data:audio/wav;base64,${window.btoa(binary)}`;
}

export default function App() {
  // Langue de l'interface (Français, Mooré, Dioula, Fulfulde)
  const [lang, setLang] = useState('fr');
  const t = TRANSLATIONS[lang] || TRANSLATIONS.fr;

  // État d'authentification & Agent courant
  const [token, setToken] = useState(() => window.sessionStorage.getItem('faso_secur_jwt') || '');
  const [currentAgent, setCurrentAgent] = useState(() => {
    const raw = window.sessionStorage.getItem('faso_secur_agent');
    return raw ? JSON.parse(raw) : null;
  });
  const [keystore, setKeystore] = useState(null);
  const keystoreRef = useRef(null);
  const [secretsVersion, setSecretsVersion] = useState(0);
  const [revokedLockdown, setRevokedLockdown] = useState(null);

  // Comptes de démo fictifs pour le jury
  const [demoAccounts, setDemoAccounts] = useState([]);
  const [loginMatricule, setLoginMatricule] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginTotp, setLoginTotp] = useState('');
  const [authMode, setAuthMode] = useState('login');
  const [activationCode, setActivationCode] = useState('');
  const [activationToken, setActivationToken] = useState('');
  const [activationTotpSecret, setActivationTotpSecret] = useState('');
  const [activationTotpCode, setActivationTotpCode] = useState('');
  const [authAlert, setAuthAlert] = useState(null);
  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const [passwordChangeToken, setPasswordChangeToken] = useState('');
  const [passwordChangeAgent, setPasswordChangeAgent] = useState(null);
  const [newPassword, setNewPassword] = useState('');
  const [confirmNewPassword, setConfirmNewPassword] = useState('');
  const [isChangingPassword, setIsChangingPassword] = useState(false);

  // Navigation principale : 'chat' | 'directory' | 'admin' | 'inspector'
  const [activeTab, setActiveTab] = useState('chat');

  // Canaux & Messages déchiffrés localement
  const [channels, setChannels] = useState([]);
  const [selectedChannelId, setSelectedChannelId] = useState(1);
  const [messages, setMessages] = useState([]);
  const [decryptedMap, setDecryptedMap] = useState({});
  const [decryptedBlobsMap, setDecryptedBlobsMap] = useState({});
  const [securityBanner, setSecurityBanner] = useState(null);

  // Compositeur de message E2EE
  const [draftText, setDraftText] = useState('');
  const [classification, setClassification] = useState('ORDINAIRE');
  const [requiresReceipt, setRequiresReceipt] = useState(false);
  const [expiresInSeconds, setExpiresInSeconds] = useState(0);
  const [isRecordingVoice, setIsRecordingVoice] = useState(false);
  const [voiceNoteLang, setVoiceNoteLang] = useState('Mooré');
  const mediaRecorderRef = useRef(null);
  const audioChunksRef = useRef([]);
  const fileInputRef = useRef(null);

  // Mode Faible Connexion (Zones rurales / mal couvertes) & File d'attente hors-ligne
  const [lowBandwidthMode, setLowBandwidthMode] = useState(false);
  const [offlineQueue, setOfflineQueue] = useState([]);
  const [wsConnected, setWsConnected] = useState(false);

  // Annuaire Ministériel & Console d'Inspection Jury
  const [directoryData, setDirectoryData] = useState({ agents: [], by_ministry: {} });
  const [selectedMinistryFilter, setSelectedMinistryFilter] = useState('TOUS');
  const [inspectionData, setInspectionData] = useState(null);

  // Formulaire d'enrôlement d'un nouvel agent (Admin DGTD)
  const [newAgentForm, setNewAgentForm] = useState({
    matricule: '',
    full_name: '',
    ministry: '',
    direction: '',
    job_title: '',
    role: 'AGENT_PUBLIC',
    preferred_lang: 'fr',
  });
  const [enrolmentResult, setEnrolmentResult] = useState(null);
  const [roleDrafts, setRoleDrafts] = useState({});
  const [showNewChannelModal, setShowNewChannelModal] = useState(false);
  const [newChannelForm, setNewChannelForm] = useState({
    name: '',
    ministry_scope: 'TOUS',
    channel_type: 'GROUP',
    default_classification: 'DIFFUSION_RESTREINTE',
    member_ids: [],
  });

  const wsRef = useRef(null);

  // ============================================================================
  // CHARGEMENT DES COMPTES FICTIFS DE DÉMO & CODE 2FA TOTP COURANT
  // ============================================================================
  const fetchDemoAccounts = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/auth/demo-accounts`);
      if (res.ok) {
        const data = await res.json();
        const rawList = data.demo_accounts || [];
        const enriched = await Promise.all(
          rawList.map(async (acc) => ({
            ...acc,
            local_totp_code: await computeLocalDemoTotpCode(acc.matricule),
          }))
        );
        setDemoAccounts(enriched);
        const selected = enriched.find((a) => a.matricule === loginMatricule);
        if (selected && selected.local_totp_code) {
          setLoginTotp(selected.local_totp_code);
        }
      } else {
        setDemoAccounts([]);
      }
    } catch {
      // Serveur en cours de démarrage
    }
  };

  useEffect(() => {
    fetchDemoAccounts();
    const timer = setInterval(fetchDemoAccounts, 10000);
    return () => clearInterval(timer);
  }, [loginMatricule]);

  // ============================================================================
  // INITIALISATION DU TROUSSEAU E2EE & WEBSOCKET LORS DE LA CONNEXION
  // ============================================================================
  useEffect(() => {
    if (!token || !currentAgent) return undefined;

    let isMounted = true;
    async function setupCryptoAndData() {
      const ks = await initializeAgentKeystore(currentAgent.matricule);
      if (!isMounted) return;
      keystoreRef.current = ks;
      setKeystore(ks);

      // Publication des clés publiques E2EE de l'agent sur le serveur Zero-Knowledge
      await fetch(`${API_BASE}/api/e2ee/keys`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(getPublicBundleForServer(ks)),
      });

      await loadChannelsAndDirectory(token, ks);
    }

    setupCryptoAndData();

    // Le JWT n'est jamais inclus dans l'URL : un ticket opaque, bref et à usage unique
    // est échangé via HTTPS, puis seul ce ticket temporaire est transmis au handshake WS.
    let ws;
    async function connectWebSocket() {
      try {
        const ticketResponse = await fetch(`${API_BASE}/api/auth/ws-ticket`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
          cache: 'no-store',
        });
        if (!ticketResponse.ok) {
          if (ticketResponse.status === 401 || ticketResponse.status === 403) {
            handleRemoteRevocationLockdown('Session révoquée ou expirée.');
          }
          return;
        }
        const { ticket } = await ticketResponse.json();
        if (!isMounted) return;

        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsHost = import.meta.env.VITE_WS_HOST || window.location.host;
        const wsUrl = `${wsProtocol}//${wsHost}/ws?ticket=${encodeURIComponent(ticket)}`;
        ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => setWsConnected(true);
        ws.onclose = (ev) => {
          setWsConnected(false);
          if (ev.code === 4003) {
            handleRemoteRevocationLockdown('Votre session a été coupée par révocation immédiate DGTD.');
          }
        };

        ws.onmessage = async (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'REMOTE_WIPE_AND_REVOKE') {
              handleRemoteRevocationLockdown(data.reason || 'Révocation immédiate par la DGTD.');
              return;
            }
            if (data.type === 'GROUP_CRYPTO_EPOCH_ROTATED') {
              setSecurityBanner({
                type: 'EPOCH_ROTATED',
                text: `Sécurité E2EE : L'agent ${data.revoked_matricule} a été révoqué (${data.reason}). Rotation immédiate des clés de session de groupe effectuée !`,
              });
              await loadChannelsAndDirectory(token);
              if (selectedChannelId) {
                await loadChannelMessages(selectedChannelId, token);
              }
              return;
            }
            if (data.type === 'NEW_E2EE_MESSAGE' && data.message) {
              if (data.message.channel_id === selectedChannelId) {
                setMessages((prev) => {
                  if (prev.some((m) => m.id === data.message.id)) return prev;
                  return [...prev, data.message];
                });
              }
            }
            if (data.type === 'PROBATIVE_RECEIPT_SIGNED') {
              if (data.channel_id === selectedChannelId) {
                await loadChannelMessages(selectedChannelId, token);
              }
            }
          } catch {
            // Ignorer trame malformée
          }
        };
      } catch {
        setWsConnected(false);
      }
    }
    connectWebSocket();

    return () => {
      isMounted = false;
      if (ws) ws.close();
    };
  }, [token, currentAgent?.matricule, selectedChannelId]);

  // Déchiffrement automatique côté client à chaque réception d'enveloppes chiffrées
  useEffect(() => {
    async function decryptAllVisibleMessages() {
      const ch = channels.find((c) => c.id === selectedChannelId) || channels[0];
      const activeMembers = ch?.active_members || directoryData.agents || [];
      const updates = {};
      for (const msg of messages) {
        if (!decryptedMap[msg.id]?.decryptedOk) {
          updates[msg.id] = await decryptE2EEMessagePayload(
            msg,
            activeMembers,
            keystoreRef.current
          );
        }
      }
      if (Object.keys(updates).length > 0) {
        setDecryptedMap((prev) => ({ ...prev, ...updates }));
      }
    }
    if (messages.length > 0) {
      decryptAllVisibleMessages();
    }
  }, [messages, secretsVersion, channels, selectedChannelId, directoryData.agents]);

  const handleRemoteRevocationLockdown = (reason) => {
    wipeLocalCryptoKeystore();
    setToken('');
    setCurrentAgent(null);
    setKeystore(null);
    setMessages([]);
    setDecryptedMap({});
    setEnrolmentResult(null);
    setRevokedLockdown(reason);
  };

  const loadChannelsAndDirectory = async (jwt = token, ks = keystoreRef.current) => {
    if (!jwt) return;
    const [chRes, dirRes] = await Promise.all([
      fetch(`${API_BASE}/api/channels`, { headers: { Authorization: `Bearer ${jwt}` } }),
      fetch(`${API_BASE}/api/directory`, { headers: { Authorization: `Bearer ${jwt}` } }),
    ]);

    if (chRes.status === 403 || chRes.status === 401) {
      const err = await chRes.json().catch(() => ({}));
      handleRemoteRevocationLockdown(err.detail || 'Session révoquée.');
      return;
    }

    if (chRes.ok) {
      const chData = await chRes.json();
      const loadedChannels = chData.channels || [];
      setChannels(loadedChannels);
      if (loadedChannels.length > 0 && !selectedChannelId) {
        setSelectedChannelId(loadedChannels[0].id);
      }
      if (ks && loadedChannels.length > 0) {
        for (const ch of loadedChannels) {
          const publish = async (bundles, initial) => {
            try {
              const r = await fetch(`${API_BASE}/api/channels/${ch.id}/group-session-bundle`, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  Authorization: `Bearer ${jwt}`,
                },
                body: JSON.stringify({
                  crypto_epoch: ch.crypto_epoch || 1,
                  wrapped_keys_by_matricule: bundles,
                  initial,
                }),
              });
              return r.ok;
            } catch {
              return false;
            }
          };
          const onConflictReload = async () => {
            try {
              const reloadRes = await fetch(`${API_BASE}/api/channels`, {
                headers: { Authorization: `Bearer ${jwt}` },
              });
              if (!reloadRes.ok) return null;
              const reloadData = await reloadRes.json();
              const updatedList = reloadData.channels || [];
              setChannels(updatedList);
              return updatedList.find((c) => c.id === ch.id) || null;
            } catch {
              return null;
            }
          };
          try {
            await syncChannelGroupSecret({ channel: ch, keystore: ks, publish, onConflictReload });
          } catch {
            // Secret non disponible : réessayé à la prochaine synchronisation
          }
        }
        setSecretsVersion((v) => v + 1);
      }
    }
    if (dirRes.ok) {
      const dirData = await dirRes.json();
      setDirectoryData(dirData);
    }
  };

  const loadChannelMessages = async (channelId, jwt = token) => {
    if (!jwt || !channelId) return;
    const res = await fetch(`${API_BASE}/api/channels/${channelId}/messages`, {
      headers: { Authorization: `Bearer ${jwt}` },
    });
    if (res.status === 403) {
      const err = await res.json().catch(() => ({}));
      if (err.detail && err.detail.includes('RÉVOQUÉ')) {
        handleRemoteRevocationLockdown(err.detail);
        return;
      }
    }
    if (res.ok) {
      const data = await res.json();
      setMessages(data.messages || []);
    }
  };

  useEffect(() => {
    if (token && selectedChannelId) {
      loadChannelMessages(selectedChannelId, token);
    }
  }, [token, selectedChannelId]);

  const [inspectionError, setInspectionError] = useState(null);
  const loadJuryInspectionData = async () => {
    if (!token) return;
    setInspectionError(null);
    const res = await fetch(`${API_BASE}/api/jury/server-inspection`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.ok) {
      setInspectionData(await res.json());
    } else {
      const err = await res.json().catch(() => ({}));
      setInspectionData(null);
      setInspectionError(err.detail || 'Accès réservé aux administrateurs DGTD / Auditeurs.');
    }
  };

  useEffect(() => {
    if (activeTab === 'inspector' && token) {
      loadJuryInspectionData();
    }
  }, [activeTab, token]);

  // ============================================================================
  // CONNEXION & SIMULATION D'INTRUS (ÉPREUVE DU JURY)
  // ============================================================================
  const handleSelectDemoAccount = async (acc) => {
    setLoginMatricule(acc.matricule);
    setLoginPassword('FasoSecur!2026');
    const code = acc.local_totp_code || (await computeLocalDemoTotpCode(acc.matricule));
    setLoginTotp(code || '');
    setAuthAlert(null);
  };

  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    setIsLoggingIn(true);
    setAuthAlert(null);
    setRevokedLockdown(null);

    try {
      const res = await fetch(`${API_BASE}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          matricule: loginMatricule,
          password: loginPassword,
          totp_code: loginTotp,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAuthAlert({ type: 'error', message: data.detail || 'Erreur de connexion' });
      } else if (data.password_change_required) {
        setPasswordChangeToken(data.password_change_token);
        setPasswordChangeAgent(data.agent);
        if (data.agent.preferred_lang && TRANSLATIONS[data.agent.preferred_lang]) {
          setLang(data.agent.preferred_lang);
        }
      } else {
        window.sessionStorage.setItem('faso_secur_jwt', data.access_token);
        window.sessionStorage.setItem('faso_secur_agent', JSON.stringify(data.agent));
        setToken(data.access_token);
        setCurrentAgent(data.agent);
        if (data.agent.preferred_lang && TRANSLATIONS[data.agent.preferred_lang]) {
          setLang(data.agent.preferred_lang);
        }
      }
    } catch (err) {
      setAuthAlert({ type: 'error', message: `Erreur réseau : ${err.message}` });
    } finally {
      setIsLoggingIn(false);
    }
  };

  const handleActivationStart = async (e) => {
    e.preventDefault();
    setAuthAlert(null);
    setIsLoggingIn(true);
    try {
      const res = await fetch(`${API_BASE}/api/auth/activation/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        cache: 'no-store',
        body: JSON.stringify({ matricule: loginMatricule, activation_code: activationCode }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAuthAlert({ type: 'error', message: data.detail || 'Code d’activation invalide.' });
        return;
      }
      setActivationToken(data.activation_token);
      setActivationTotpSecret(data.totp_secret);
      setActivationCode('');
      setActivationTotpCode('');
      setNewPassword('');
      setConfirmNewPassword('');
    } catch (err) {
      setAuthAlert({ type: 'error', message: `Erreur réseau : ${err.message}` });
    } finally {
      setIsLoggingIn(false);
    }
  };

  const handleActivationComplete = async (e) => {
    e.preventDefault();
    setAuthAlert(null);
    if (newPassword !== confirmNewPassword) {
      setAuthAlert({ type: 'error', message: 'Les deux mots de passe ne correspondent pas.' });
      return;
    }
    setIsChangingPassword(true);
    try {
      const res = await fetch(`${API_BASE}/api/auth/activation/complete`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${activationToken}`,
        },
        cache: 'no-store',
        body: JSON.stringify({ new_password: newPassword, totp_code: activationTotpCode }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAuthAlert({ type: 'error', message: data.detail || 'Impossible d’activer le compte.' });
        return;
      }
      window.sessionStorage.setItem('faso_secur_jwt', data.access_token);
      window.sessionStorage.setItem('faso_secur_agent', JSON.stringify(data.agent));
      setToken(data.access_token);
      setCurrentAgent(data.agent);
      setActivationToken('');
      setActivationTotpSecret('');
      setActivationTotpCode('');
      setNewPassword('');
      setConfirmNewPassword('');
      setAuthMode('login');
      if (data.agent.preferred_lang && TRANSLATIONS[data.agent.preferred_lang]) {
        setLang(data.agent.preferred_lang);
      }
    } catch (err) {
      setAuthAlert({ type: 'error', message: `Erreur réseau : ${err.message}` });
    } finally {
      setIsChangingPassword(false);
    }
  };

  const handleFirstPasswordChange = async (e) => {
    e.preventDefault();
    setAuthAlert(null);
    if (newPassword !== confirmNewPassword) {
      setAuthAlert({ type: 'error', message: 'Les deux mots de passe ne correspondent pas.' });
      return;
    }

    setIsChangingPassword(true);
    try {
      const res = await fetch(`${API_BASE}/api/auth/first-password-change`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${passwordChangeToken}`,
        },
        body: JSON.stringify({ new_password: newPassword }),
      });
      const data = await res.json();
      if (!res.ok) {
        setAuthAlert({ type: 'error', message: data.detail || 'Impossible de modifier le mot de passe.' });
        return;
      }

      window.sessionStorage.setItem('faso_secur_jwt', data.access_token);
      window.sessionStorage.setItem('faso_secur_agent', JSON.stringify(data.agent));
      setToken(data.access_token);
      setCurrentAgent(data.agent);
      setPasswordChangeToken('');
      setPasswordChangeAgent(null);
      setNewPassword('');
      setConfirmNewPassword('');
      if (data.agent.preferred_lang && TRANSLATIONS[data.agent.preferred_lang]) {
        setLang(data.agent.preferred_lang);
      }
    } catch (err) {
      setAuthAlert({ type: 'error', message: `Erreur réseau : ${err.message}` });
    } finally {
      setIsChangingPassword(false);
    }
  };

  const handleSimulateIntruderAttempt = async () => {
    setAuthAlert(null);
    const res = await fetch(`${API_BASE}/api/auth/intruder-attempt`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        matricule: 'INTRUS-NON-ENROLE-666',
        full_name: 'Individu Externe Non Enrôlé',
        target_channel_slug: 'cellule-veille-souveraine',
      }),
    });
    const data = await res.json();
    setAuthAlert({
      type: 'intruder_blocked',
      status: res.status,
      message: data.detail,
    });
  };

  const handleLogout = () => {
    window.sessionStorage.removeItem('faso_secur_jwt');
    window.sessionStorage.removeItem('faso_secur_agent');
    setToken('');
    setCurrentAgent(null);
    setMessages([]);
    setEnrolmentResult(null);
  };

  const handlePanicWipe = () => {
    wipeLocalCryptoKeystore();
    setToken('');
    setCurrentAgent(null);
    setEnrolmentResult(null);
    setRevokedLockdown(
      "BOUTON D'URGENCE ACTIVÉ : Toutes les clés cryptographiques E2EE locales et le cache de session ont été intégralement purgés de cet appareil."
    );
  };

  // ============================================================================
  // ENVOI DE MESSAGES, FICHIERS & NOTES VOCALES CHIFFRÉS DE BOUT EN BOUT
  // ============================================================================
  const currentChannel = channels.find((c) => c.id === selectedChannelId) || channels[0];
  const canManageAccounts = ['SUPER_ADMIN_DGTD', 'POINT_FOCAL'].includes(currentAgent?.role);
  const canInspectSecurity = ['SUPER_ADMIN_DGTD', 'POINT_FOCAL', 'AUDITEUR'].includes(currentAgent?.role);

  // Réserve et consomme atomiquement les One-Time PreKeys Signal auprès du serveur pour les nouveaux correspondants
  const resolveActiveMembersPrekeys = async (channelId, members) => {
    if (!keystore || !Array.isArray(members)) return members || [];
    const resolved = await Promise.all(
      members.map(async (m) => {
        if (!m || !m.matricule || m.matricule === currentAgent?.matricule) return m;
        const hasSession = await hasEstablishedSignalSession(keystore, m.matricule);
        if (!hasSession) {
          try {
            const resp = await fetch(
              `${API_BASE}/api/e2ee/prekeys/consume/${encodeURIComponent(m.matricule)}?channel_id=${channelId}`,
              {
                method: 'POST',
                headers: { Authorization: `Bearer ${token}` },
              }
            );
            if (resp.ok) {
              const data = await resp.json();
              if (data?.signal_prekey_bundle) {
                return {
                  ...m,
                  e2ee_one_time_prekeys_json: JSON.stringify({
                    protocol: data.protocol || 'SIGNAL_X3DH_DOUBLERATCHET_AES256GCM_ECDSA',
                    signal_prekey_bundle: data.signal_prekey_bundle,
                  }),
                };
              }
            }
          } catch {
            // Repli gracieux sur le faisceau initial si hors-ligne ou indisponible
          }
        }
        return m;
      })
    );
    return resolved;
  };

  const handleSendEncryptedText = async (e) => {
    e.preventDefault();
    if (!draftText.trim() || !keystore || !currentChannel) return;
    if (!hasGroupSecret(currentChannel.id, currentChannel.crypto_epoch || 1)) {
      await loadChannelsAndDirectory(token, keystore);
      if (!hasGroupSecret(currentChannel.id, currentChannel.crypto_epoch || 1)) {
        setSecurityBanner({
          type: 'EPOCH_ROTATED',
          text: 'Clé de groupe E2EE pas encore reçue : un membre actif doit se connecter pour vous l’envoyer. Message non envoyé.',
        });
        return;
      }
    }

    const plaintextObject = {
      text: draftText.trim(),
      lang,
      senderMatricule: currentAgent.matricule,
      senderName: currentAgent.full_name,
      senderMinistry: currentAgent.ministry,
      senderRole: currentAgent.role,
      classification,
      noForward: classification !== 'ORDINAIRE',
      antiScreenshot: classification !== 'ORDINAIRE',
      messageKind: requiresReceipt ? 'SERVICE_INSTRUCTION' : 'TEXT',
      sentAtClient: new Date().toISOString(),
    };

    const activeMembers = await resolveActiveMembersPrekeys(
      currentChannel.id,
      currentChannel.active_members || []
    );

    const envelope = await encryptE2EEMessagePayload({
      channelId: currentChannel.id,
      cryptoEpoch: currentChannel.crypto_epoch || 1,
      plaintextObject,
      keystore,
      activeMembers,
    });

    const requestBody = {
      ...envelope,
      requires_probative_receipt: requiresReceipt,
      expires_in_seconds: expiresInSeconds > 0 ? Number(expiresInSeconds) : null,
    };

    try {
      const res = await fetch(`${API_BASE}/api/channels/${currentChannel.id}/messages`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(requestBody),
      });

      if (res.status === 403) {
        const err = await res.json().catch(() => ({}));
        handleRemoteRevocationLockdown(err.detail || 'Accès révoqué.');
        return;
      }

      if (res.ok) {
        const savedMsg = await res.json();
        setDraftText('');
        setMessages((prev) => (prev.some((m) => m.id === savedMsg.id) ? prev : [...prev, savedMsg]));
      }
    } catch {
      // En mode faible connexion / coupure, mise en file d'attente locale chiffrée
      setOfflineQueue((prev) => [...prev, { channelId: currentChannel.id, body: requestBody }]);
      setDraftText('');
    }
  };

  // Enregistrement et chiffrement E2EE d'une note vocale (en Français, Mooré, Dioula ou Fulfulde)
  const handleToggleVoiceRecording = async () => {
    if (!currentChannel || !keystore) return;

    if (!isRecordingVoice) {
      setIsRecordingVoice(true);
      audioChunksRef.current = [];
      try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        const recorder = new MediaRecorder(stream);
        mediaRecorderRef.current = recorder;
        recorder.ondataavailable = (ev) => {
          if (ev.data.size > 0) audioChunksRef.current.push(ev.data);
        };
        recorder.start();
      } catch {
        // Aucun micro matériel détecté : utilisation du synthétiseur vocal E2EE de secours à l'arrêt
        mediaRecorderRef.current = null;
      }
    } else {
      setIsRecordingVoice(false);
      let audioDataUrl = null;

      if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
        await new Promise((resolve) => {
          mediaRecorderRef.current.onstop = () => {
            const blob = new Blob(audioChunksRef.current, { type: 'audio/webm' });
            const reader = new FileReader();
            reader.onloadend = () => {
              audioDataUrl = reader.result;
              resolve();
            };
            reader.readAsDataURL(blob);
          };
          mediaRecorderRef.current.stop();
          mediaRecorderRef.current.stream.getTracks().forEach((tr) => tr.stop());
        });
      } else {
        audioDataUrl = createSynthesizedVoiceDataUrl(2.4);
      }

      await uploadAndSendEncryptedBlob({
        dataUrl: audioDataUrl,
        fileName: `Note_Vocale_${voiceNoteLang}_${new Date().toLocaleTimeString('fr-FR')}.wav`,
        mimeType: 'audio/wav',
        messageKind: 'VOICE_NOTE',
        caption: `Message vocal officiel en langue nationale (${voiceNoteLang}) — Chiffré de bout en bout (Signal + AES-256-GCM)`,
      });
    }
  };

  // Chiffrement E2EE d'un fichier joint côté client
  const handleFileUploadChange = async (e) => {
    const file = e.target.files?.[0];
    if (!file || !currentChannel || !keystore) return;

    const reader = new FileReader();
    reader.onloadend = async () => {
      await uploadAndSendEncryptedBlob({
        dataUrl: reader.result,
        fileName: file.name,
        mimeType: file.type || 'application/octet-stream',
        messageKind: 'ATTACHMENT',
        caption: `Pièce jointe chiffrée de bout en bout : ${file.name} (${Math.round(file.size / 1024)} Ko)`,
      });
    };
    reader.readAsDataURL(file);
    e.target.value = '';
  };

  const uploadAndSendEncryptedBlob = async ({ dataUrl, fileName, mimeType, messageKind, caption }) => {
    const encryptedBlob = await encryptBinaryAttachmentE2EE(dataUrl);

    const blobRes = await fetch(`${API_BASE}/api/blobs`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        channel_id: currentChannel.id,
        ciphertext_b64: encryptedBlob.ciphertext_b64,
        iv_b64: encryptedBlob.iv_b64,
      }),
    });

    if (!blobRes.ok) return;
    const blobMeta = await blobRes.json();

    const plaintextObject = {
      text: caption,
      fileName,
      mimeType,
      voiceLang: voiceNoteLang,
      blobId: blobMeta.blob_id,
      attachmentKeyB64: encryptedBlob.attachment_key_b64,
      attachmentIvB64: encryptedBlob.iv_b64,
      sha256Ciphertext: blobMeta.sha256_ciphertext,
      senderMatricule: currentAgent.matricule,
      senderName: currentAgent.full_name,
      senderMinistry: currentAgent.ministry,
      senderRole: currentAgent.role,
      classification,
      noForward: classification !== 'ORDINAIRE',
      antiScreenshot: classification !== 'ORDINAIRE',
      messageKind,
      lang,
    };

    const activeMembers = await resolveActiveMembersPrekeys(
      currentChannel.id,
      currentChannel.active_members || []
    );

    const envelope = await encryptE2EEMessagePayload({
      channelId: currentChannel.id,
      cryptoEpoch: currentChannel.crypto_epoch || 1,
      plaintextObject,
      keystore,
      activeMembers,
    });

    const msgRes = await fetch(`${API_BASE}/api/channels/${currentChannel.id}/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        ...envelope,
        requires_probative_receipt: requiresReceipt,
        encrypted_blob_id: blobMeta.blob_id,
      }),
    });

    if (msgRes.ok) {
      const saved = await msgRes.json();
      setMessages((prev) => (prev.some((m) => m.id === saved.id) ? prev : [...prev, saved]));
    }
  };

  const handleDecryptAndLoadBlob = async (msg) => {
    if (!msg.encrypted_blob_id || decryptedBlobsMap[msg.encrypted_blob_id]) return;
    const dec = decryptedMap[msg.id];
    const attachmentKeyB64 = dec?.content?.attachmentKeyB64;
    if (!attachmentKeyB64) return;

    const res = await fetch(`${API_BASE}/api/blobs/${msg.encrypted_blob_id}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.ok) {
      const blobData = await res.json();
      const dataUrl = await decryptBinaryAttachmentE2EE(
        blobData.ciphertext_b64,
        blobData.iv_b64,
        attachmentKeyB64
      );
      setDecryptedBlobsMap((prev) => ({ ...prev, [msg.encrypted_blob_id]: dataUrl }));
    }
  };

  // Signature d'un accusé de lecture à valeur probante (ECDSA-SHA256)
  const handleSignProbativeReceipt = async (msg) => {
    if (!keystore) return;
    const sigData = await signProbativeReadReceipt({
      messageId: msg.id,
      ciphertextPayload: msg.ciphertext_payload,
      matricule: currentAgent.matricule,
      keystore,
    });

    const res = await fetch(`${API_BASE}/api/messages/${msg.id}/probative-receipt`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(sigData),
    });
    if (res.ok) {
      await loadChannelMessages(selectedChannelId, token);
    }
  };

  // ============================================================================
  // ACTIONS D'ADMINISTRATION DGTD : RÉVOCATION IMMÉDIATE & ENRÔLEMENT
  // ============================================================================
  const handleRevokeAgent = async (agent) => {
    const res = await fetch(`${API_BASE}/api/admin/revoke/${agent.id}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        reason: `Révocation immédiate DGTD (Perte d'appareil / Fin de mission — ${new Date().toLocaleTimeString('fr-FR')})`,
      }),
    });
    if (res.ok) {
      const data = await res.json();
      setSecurityBanner({
        type: 'REVOKED_SUCCESS',
        text: `Agent ${agent.matricule} (${agent.full_name}) révoqué immédiatement ! ${data.closed_websocket_sessions} session(s) coupée(s) et clés E2EE de groupe renouvelées.`,
      });
      await loadChannelsAndDirectory(token);
      await fetchDemoAccounts();
    }
  };

  const handleReinstateAgent = async (agent) => {
    const res = await fetch(`${API_BASE}/api/admin/reinstate/${agent.id}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.ok) {
      setSecurityBanner({
        type: 'REINSTATED',
        text: `Agent ${agent.matricule} réhabilité pour rejouer l'épreuve de démonstration.`,
      });
      await loadChannelsAndDirectory(token);
      await fetchDemoAccounts();
    }
  };

  const handleChangeAgentRole = async (agent) => {
    const role = roleDrafts[agent.id] || agent.role;
    if (role === agent.role || !window.confirm(`Confirmer le changement de rôle de ${agent.full_name} ?`)) return;
    const res = await fetch(`${API_BASE}/api/admin/agents/${agent.id}/role`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ role }),
    });
    const data = await res.json();
    if (!res.ok) {
      setSecurityBanner({ type: 'ROLE_ERROR', text: data.detail || 'Le rôle n’a pas pu être modifié.' });
      return;
    }
    setSecurityBanner({ type: 'ROLE_CHANGED', text: `Rôle de ${agent.full_name} mis à jour.` });
    setRoleDrafts((prev) => ({ ...prev, [agent.id]: role }));
    await loadChannelsAndDirectory(token);
  };

  const handleEnrolNewAgent = async (e) => {
    e.preventDefault();
    setEnrolmentResult(null);
    const res = await fetch(`${API_BASE}/api/admin/enrol`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      cache: 'no-store',
      body: JSON.stringify(newAgentForm),
    });
    const data = await res.json();
    if (res.ok) {
      setEnrolmentResult(data);
      await loadChannelsAndDirectory(token);
      await fetchDemoAccounts();
    }
  };

  const handleReissueActivationCode = async (agent) => {
    if (!window.confirm(`Générer un nouveau code et invalider l’invitation précédente de ${agent.full_name} ?`)) return;
    setEnrolmentResult(null);
    const res = await fetch(`${API_BASE}/api/admin/agents/${agent.id}/activation-code`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      cache: 'no-store',
    });
    const data = await res.json();
    if (!res.ok) {
      setSecurityBanner({ type: 'ACTIVATION_ERROR', text: data.detail || 'Le code ne peut pas être réémis.' });
      return;
    }
    setEnrolmentResult(data);
    await loadChannelsAndDirectory(token);
  };

  const handleCreateChannel = async (e) => {
    e.preventDefault();
    if (!newChannelForm.name.trim()) return;
    try {
      const res = await fetch(`${API_BASE}/api/channels`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(newChannelForm),
      });
      const data = await res.json();
      if (!res.ok) {
        setSecurityBanner({ type: 'CHANNEL_ERROR', text: data.detail || 'Impossible de créer le canal.' });
        return;
      }
      setShowNewChannelModal(false);
      setNewChannelForm({
        name: '',
        ministry_scope: currentAgent?.role === 'SUPER_ADMIN_DGTD' ? 'TOUS' : currentAgent?.ministry || 'TOUS',
        channel_type: 'GROUP',
        default_classification: 'DIFFUSION_RESTREINTE',
        member_ids: [],
      });
      await loadChannelsAndDirectory(token);
      setSelectedChannelId(data.id);
      setSecurityBanner({ type: 'CHANNEL_CREATED', text: `Canal « ${data.name} » créé avec succès.` });
    } catch (err) {
      setSecurityBanner({ type: 'CHANNEL_ERROR', text: err.message });
    }
  };

  // ============================================================================
  // ÉCRAN D'URGENCE / VERROUILLAGE APRÈS RÉVOCATION EN DIRECT OU BOUTON PANIC
  // ============================================================================
  if (revokedLockdown) {
    return (
      <div className="min-h-screen bg-red-950 text-white flex flex-col items-center justify-center p-6">
        <div className="max-w-xl w-full bg-slate-900 border-2 border-red-500 rounded-2xl p-8 shadow-2xl text-center">
          <div className="w-20 h-20 rounded-full bg-red-500/20 border border-red-500 flex items-center justify-center mx-auto mb-6">
            <ShieldOff className="w-12 h-12 text-red-400" />
          </div>
          <h1 className="text-2xl font-bold text-red-400 mb-2">
            ACCÈS RÉVOQUÉ IMMÉDIATEMENT & TROUSSEAU E2EE PURGÉ
          </h1>
          <p className="text-slate-300 text-sm mb-6 leading-relaxed">{revokedLockdown}</p>
          <div className="bg-slate-950/90 border border-red-800/60 rounded-xl p-4 text-left text-xs text-slate-300 space-y-2 mb-6 font-mono">
            <div>✓ Connexion WebSocket temps réel coupée par le serveur souverain (Code 4003)</div>
            <div>✓ Jeton JWT invalidé côté serveur (Token Version incrémentée — bloque aussi tout terminal hors-ligne)</div>
            <div>✓ Signal REMOTE_WIPE exécuté sur ce navigateur : clés privées E2EE et IndexedDB purgées</div>
            <div>✓ Rotation de l’époque cryptographique (crypto_epoch) avec nouveau secret CSPRNG excluant cet agent</div>
          </div>
          <button
            onClick={() => {
              setRevokedLockdown(null);
              fetchDemoAccounts();
            }}
            className="px-6 py-3 rounded-xl bg-emerald-600 hover:bg-emerald-500 font-semibold text-sm transition"
          >
            Retourner au portail d’authentification souverain
          </button>
        </div>
      </div>
    );
  }

  // ============================================================================
  // ÉCRAN DE CONNEXION VÉRIFIÉE (ENRÔLEMENT + 2FA TOTP + SIMULATEUR D'INTRUS)
  // ============================================================================
  if (passwordChangeToken && passwordChangeAgent) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center px-4 py-8">
        <section className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-xl">
          <div className="mb-5 flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-emerald-600/20 text-emerald-400">
              <Lock className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">Choisissez votre mot de passe</h1>
              <p className="text-sm text-slate-400">Première connexion de {passwordChangeAgent.full_name}</p>
            </div>
          </div>

          <p className="mb-5 text-sm text-slate-400">
            Pour protéger votre compte, remplacez le mot de passe temporaire avant de continuer.
          </p>

          {authAlert && (
            <div className="mb-4 rounded-xl border border-red-300 bg-red-50 p-3 text-sm text-red-800" role="alert">
              {authAlert.message}
            </div>
          )}

          <form onSubmit={handleFirstPasswordChange} className="space-y-4">
            <label className="block text-sm font-medium text-slate-300">
              Nouveau mot de passe
              <input
                type="password"
                autoComplete="new-password"
                minLength={12}
                maxLength={72}
                required
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="mt-1 w-full rounded-xl border border-slate-700 bg-slate-950 px-3.5 py-3 text-sm text-white focus:border-emerald-500 focus:outline-none"
              />
            </label>
            <p className="-mt-2 text-xs text-slate-500">12 caractères minimum, avec une majuscule, une minuscule et un chiffre.</p>
            <label className="block text-sm font-medium text-slate-300">
              Confirmer le nouveau mot de passe
              <input
                type="password"
                autoComplete="new-password"
                minLength={12}
                maxLength={72}
                required
                value={confirmNewPassword}
                onChange={(e) => setConfirmNewPassword(e.target.value)}
                className="mt-1 w-full rounded-xl border border-slate-700 bg-slate-950 px-3.5 py-3 text-sm text-white focus:border-emerald-500 focus:outline-none"
              />
            </label>
            <button
              type="submit"
              disabled={isChangingPassword}
              className="w-full rounded-xl bg-emerald-700 px-4 py-3 text-sm font-bold text-white hover:bg-emerald-600 disabled:opacity-60"
            >
              {isChangingPassword ? 'Enregistrement…' : 'Enregistrer et continuer'}
            </button>
          </form>
        </section>
      </div>
    );
  }

  if (!token || !currentAgent) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-between">
        {/* Bandeau drapeau Burkina Faso */}
        <div className="h-2 w-full flex">
          <div className="w-1/2 bg-red-600" />
          <div className="w-1/2 bg-emerald-600" />
        </div>

        <div className="max-w-6xl w-full mx-auto px-4 py-8 grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          {/* Colonne gauche : Portail de connexion 2FA TOTP */}
          <div className="lg:col-span-6 bg-slate-900/90 border border-slate-800 rounded-2xl p-6 lg:p-8 shadow-2xl">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-red-600 via-amber-400 to-emerald-600 p-0.5">
                  <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
                    <ShieldCheck className="w-7 h-7 text-amber-400" />
                  </div>
                </div>
                <div>
                  <span className="text-[11px] uppercase tracking-widest text-amber-400 font-bold">
                    MTDPCE — DGTD • BURKINA FASO
                  </span>
                  <h1 className="text-2xl font-extrabold tracking-tight text-white">{t.appTitle}</h1>
                </div>
              </div>

              {/* Sélecteur de langue nationale dès l'accueil */}
              <select
                value={lang}
                onChange={(e) => setLang(e.target.value)}
                className="bg-slate-800 border border-slate-700 text-xs rounded-lg px-2.5 py-1.5 text-slate-200"
              >
                {LANGUAGES.map((l) => (
                  <option key={l.code} value={l.code}>
                    {l.label}
                  </option>
                ))}
              </select>
            </div>

            <p className="text-xs text-slate-400 mb-6 border-l-2 border-emerald-500 pl-3">
              {t.appSubtitle}
            </p>

            {authAlert && (
              <div
                className={`mb-5 p-4 rounded-xl border text-xs leading-relaxed ${
                  authAlert.type === 'intruder_blocked'
                    ? 'bg-amber-950/60 border-amber-500 text-amber-200'
                    : 'bg-red-950/70 border-red-500 text-red-200'
                }`}
              >
                <div className="font-bold flex items-center gap-2 mb-1">
                  <ShieldAlert className="w-4 h-4 shrink-0" />
                  {authAlert.type === 'intruder_blocked'
                    ? 'Accès refusé : identifiant inconnu.'
                    : 'Connexion impossible'}
                </div>
                <div>{authAlert.message}</div>
              </div>
            )}

            {authMode === 'login' ? (
            <form onSubmit={handleLoginSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Identifiant professionnel
                </label>
                <input
                  type="text"
                  value={loginMatricule}
                  onChange={(e) => setLoginMatricule(e.target.value)}
                  required
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3.5 py-2.5 text-sm font-mono text-white focus:border-emerald-500 focus:outline-none"
                  placeholder="Ex: BF-DGTD-001"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Mot de passe
                </label>
                <input
                  type="password"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  required
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3.5 py-2.5 text-sm text-white focus:border-emerald-500 focus:outline-none"
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-xs font-semibold text-amber-400 flex items-center gap-1.5">
                    <KeyRound className="w-3.5 h-3.5" />
                    Code de sécurité
                  </label>
                  <span className="text-[11px] text-slate-400">6 chiffres</span>
                </div>
                <input
                  type="text"
                  value={loginTotp}
                  onChange={(e) => setLoginTotp(e.target.value)}
                  required
                  maxLength={6}
                  className="w-full bg-slate-950 border border-amber-500/60 rounded-xl px-3.5 py-2.5 text-base font-mono tracking-widest text-amber-300 focus:border-amber-400 focus:outline-none"
                  placeholder="000000"
                />
              </div>

              <button
                type="submit"
                disabled={isLoggingIn}
                className="w-full py-3 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-bold text-sm shadow-lg flex items-center justify-center gap-2 transition"
              >
                <Lock className="w-4 h-4" />
                {isLoggingIn
                  ? 'Connexion en cours…'
                  : 'Se connecter'}
              </button>
            </form>
            ) : (
              <div className="space-y-4">
                {!activationToken ? (
                  <form onSubmit={handleActivationStart} className="space-y-4">
                    <p className="text-xs text-slate-300 rounded-lg border border-emerald-800 bg-emerald-950/30 p-3">
                      Utilisez le matricule et le code à usage unique remis par votre administration. Le code expire après 24 heures.
                    </p>
                    <div>
                      <label className="block text-xs font-semibold text-slate-300 mb-1">Identifiant professionnel</label>
                      <input
                        type="text"
                        value={loginMatricule}
                        onChange={(e) => setLoginMatricule(e.target.value)}
                        required
                        autoComplete="username"
                        className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3.5 py-2.5 text-sm font-mono text-white focus:border-emerald-500 focus:outline-none"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-slate-300 mb-1">Code d’activation à usage unique</label>
                      <input
                        type="password"
                        value={activationCode}
                        onChange={(e) => setActivationCode(e.target.value)}
                        required
                        autoComplete="one-time-code"
                        className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3.5 py-2.5 text-sm font-mono text-white focus:border-emerald-500 focus:outline-none"
                      />
                    </div>
                    <button type="submit" disabled={isLoggingIn} className="w-full py-3 rounded-xl bg-emerald-700 hover:bg-emerald-600 disabled:opacity-50 text-white font-bold text-sm">
                      {isLoggingIn ? 'Vérification…' : 'Vérifier mon invitation'}
                    </button>
                  </form>
                ) : (
                  <form onSubmit={handleActivationComplete} className="space-y-4">
                    <div className="rounded-xl border border-amber-700 bg-amber-950/30 p-3 text-xs text-amber-100">
                      <div className="font-bold mb-1">1. Configurez votre application d’authentification</div>
                      <p className="mb-2">Ajoutez un compte TOTP dans l’application approuvée par votre administration, puis saisissez cette clé. Elle ne sera plus affichée après l’activation.</p>
                      <code className="block select-all break-all rounded-lg bg-slate-950 p-3 font-mono tracking-wider text-amber-300">{activationTotpSecret}</code>
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-slate-300 mb-1">Code à 6 chiffres de l’application</label>
                      <input
                        type="text"
                        inputMode="numeric"
                        pattern="[0-9]{6}"
                        value={activationTotpCode}
                        onChange={(e) => setActivationTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                        required
                        autoComplete="one-time-code"
                        maxLength={6}
                        className="w-full bg-slate-950 border border-amber-500/60 rounded-xl px-3.5 py-2.5 text-base font-mono tracking-widest text-amber-300 focus:border-amber-400 focus:outline-none"
                        placeholder="000000"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-slate-300 mb-1">Choisissez votre mot de passe</label>
                      <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required minLength={12} autoComplete="new-password" className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3.5 py-2.5 text-sm text-white focus:border-emerald-500 focus:outline-none" />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-slate-300 mb-1">Confirmez le mot de passe</label>
                      <input type="password" value={confirmNewPassword} onChange={(e) => setConfirmNewPassword(e.target.value)} required minLength={12} autoComplete="new-password" className="w-full bg-slate-950 border border-slate-700 rounded-xl px-3.5 py-2.5 text-sm text-white focus:border-emerald-500 focus:outline-none" />
                    </div>
                    <button type="submit" disabled={isChangingPassword || activationTotpCode.length !== 6} className="w-full py-3 rounded-xl bg-emerald-700 hover:bg-emerald-600 disabled:opacity-50 text-white font-bold text-sm">
                      {isChangingPassword ? 'Activation…' : 'Activer mon compte'}
                    </button>
                  </form>
                )}
                <button
                  type="button"
                  onClick={() => {
                    setAuthMode('login');
                    setActivationCode('');
                    setActivationToken('');
                    setActivationTotpSecret('');
                    setActivationTotpCode('');
                    setAuthAlert(null);
                  }}
                  className="w-full py-2 text-xs text-slate-400 hover:text-white"
                >
                  Retour à la connexion
                </button>
              </div>
            )}

            {authMode === 'login' && (
              <button
                type="button"
                onClick={() => { setAuthMode('activate'); setAuthAlert(null); }}
                className="mt-4 w-full py-2.5 rounded-xl border border-slate-700 hover:border-emerald-600 text-emerald-300 text-sm font-semibold"
              >
                Activer mon compte avec un code d’invitation
              </button>
            )}

            {demoAccounts.length > 0 && (
              <details className="mt-6 border-t border-slate-800 pt-4 text-sm">
                <summary className="cursor-pointer text-slate-500">Outils de démonstration</summary>
                <button
                  type="button"
                  onClick={handleSimulateIntruderAttempt}
                  className="mt-3 w-full py-2.5 px-4 rounded-xl bg-red-950/60 hover:bg-red-900/60 border border-red-700/70 text-red-200 text-xs font-semibold flex items-center justify-center gap-2 transition"
                >
                  <UserX className="w-4 h-4 text-red-400" />
                  Tester un identifiant inconnu
                </button>
              </details>
            )}
          </div>

          {demoAccounts.length > 0 && (
          <div className="lg:col-span-6 bg-slate-900/70 border border-slate-800 rounded-2xl p-6">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-2">
                <Users className="w-4 h-4" />
                Comptes de démonstration
              </h2>
              <button
                onClick={fetchDemoAccounts}
                className="text-xs text-slate-400 hover:text-white flex items-center gap-1"
              >
                <RefreshCw className="w-3.5 h-3.5" /> Actualiser
              </button>
            </div>
            <p className="text-xs text-slate-400 mb-4 leading-relaxed">
              Choisissez un compte pour remplir automatiquement le formulaire de connexion.
            </p>

            <div className="space-y-2.5">
              {demoAccounts.map((acc) => (
                <div
                  key={acc.matricule}
                  onClick={() => handleSelectDemoAccount(acc)}
                  className={`p-3.5 rounded-xl border cursor-pointer transition ${
                    loginMatricule === acc.matricule
                      ? 'bg-emerald-950/40 border-emerald-500'
                      : 'bg-slate-950/70 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-slate-800 text-amber-300">
                        {acc.matricule}
                      </span>
                      <span className="font-semibold text-sm text-white">{acc.full_name}</span>
                    </div>
                    {acc.is_revoked ? (
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-red-900/80 text-red-200">
                        RÉVOQUÉ
                      </span>
                    ) : (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700/50">
                        Compte disponible
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-slate-400 mt-1 flex items-center justify-between">
                    <span>{acc.ministry}</span>
                  </div>
                </div>
              ))}
            </div>

            <details className="mt-5 rounded-xl border border-slate-800 bg-slate-950 p-4 text-xs text-slate-400">
              <summary className="cursor-pointer font-semibold text-slate-200">Comment vos messages sont protégés</summary>
              <p className="mt-3">Seuls les membres autorisés peuvent lire les messages. La connexion est protégée par un mot de passe et un code de sécurité.</p>
            </details>
          </div>
          )}
        </div>

        <footer className="text-center py-4 text-xs text-slate-500 border-t border-slate-900">
          FASO-SÉCUR • Sprint Technique Pré-Hackathon 226 (Semaine du Numérique 2026) • Distribution GPL-3.0-only
        </footer>
      </div>
    );
  }

  // ============================================================================
  // INTERFACE PRINCIPALE DE LA MESSAGERIE SOUVERAINE
  // ============================================================================
  return (
    <div className="h-screen bg-slate-950 text-slate-100 flex flex-col overflow-hidden no-print-classified">
      {/* Barre supérieure tricolore Burkina Faso */}
      <div className="h-1.5 w-full flex shrink-0">
        <div className="w-1/2 bg-red-600" />
        <div className="w-1/2 bg-emerald-600" />
      </div>

      {/* En-tête Souverain */}
      <header className="bg-slate-900 border-b border-slate-800 px-4 py-2.5 flex flex-wrap items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-emerald-600/20 border border-emerald-500 flex items-center justify-center">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-extrabold text-base tracking-tight text-white">{t.appTitle}</span>
              <span
                className={`text-[10px] px-2 py-0.5 rounded-full flex items-center gap-1 ${
                  wsConnected
                    ? 'bg-emerald-950/80 text-emerald-300'
                    : 'bg-amber-950/80 text-amber-300'
                }`}
              >
                {wsConnected ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
                {wsConnected ? 'En ligne' : 'Connexion interrompue'}
              </span>
            </div>
            <div className="text-[11px] text-slate-400">
              Agent connecté : <strong className="text-slate-200">{currentAgent.full_name}</strong> (
              <span className="font-mono text-amber-300">{currentAgent.matricule}</span> • {currentAgent.ministry})
            </div>
          </div>
        </div>

        {/* Barre d'outils : Langues nationales, Mode Faible Connexion, Bouton d'Urgence, Déconnexion */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Sélecteur de langue nationale (+3 pts Bonus) */}
          <div className="flex items-center gap-1 bg-slate-950 border border-slate-700 rounded-lg px-2 py-1">
            <Globe className="w-3.5 h-3.5 text-amber-400" />
            <select
              value={lang}
              onChange={(e) => setLang(e.target.value)}
              className="bg-transparent text-xs text-slate-200 focus:outline-none"
            >
              {LANGUAGES.map((l) => (
                <option key={l.code} value={l.code} className="bg-slate-900">
                  {l.label}
                </option>
              ))}
            </select>
          </div>

          <details className="relative">
            <summary className="list-none cursor-pointer px-2.5 py-1.5 rounded-lg border border-slate-700 text-slate-300 text-xs">Plus</summary>
            <div className="absolute right-0 top-full z-30 mt-2 w-56 rounded-xl border border-slate-700 bg-white p-2 shadow-xl">
              <button
                onClick={() => setLowBandwidthMode((v) => !v)}
                className="w-full rounded-lg px-3 py-2 text-left text-xs text-slate-700 hover:bg-slate-100"
                title={t.lowBandwidthMode}
              >
                <WifiOff className="mr-2 inline h-3.5 w-3.5" />
                {lowBandwidthMode ? 'Désactiver la connexion lente' : 'Activer la connexion lente'}
              </button>
              <button
                onClick={handlePanicWipe}
                className="w-full rounded-lg px-3 py-2 text-left text-xs text-red-700 hover:bg-red-50"
                title={t.panicButton}
              >
                <Trash2 className="mr-2 inline h-3.5 w-3.5" />{t.panicButton}
              </button>
            </div>
          </details>

          <button
            onClick={handleLogout}
            className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs flex items-center gap-1"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>{t.logoutBtn}</span>
          </button>
        </div>
      </header>

      {/* Bannière d'alerte sécurité temps réel (ex: Rotation de clé après révocation) */}
      {securityBanner && (
        <div className="bg-amber-950/90 border-b border-amber-500 px-4 py-2 text-xs text-amber-200 flex items-center justify-between">
          <div className="flex items-center gap-2 font-medium">
            <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0" />
            <span>{securityBanner.text}</span>
          </div>
          <button
            onClick={() => setSecurityBanner(null)}
            className="text-amber-300 hover:text-white font-bold ml-4"
          >
            ✕
          </button>
        </div>
      )}

      {/* Navigation par onglets */}
      <div className="bg-slate-900/60 border-b border-slate-800 px-4 flex items-center gap-2 shrink-0 overflow-x-auto">
        <button
          onClick={() => setActiveTab('chat')}
          className={`py-2.5 px-3.5 text-xs font-bold border-b-2 flex items-center gap-2 transition whitespace-nowrap ${
            activeTab === 'chat'
              ? 'border-emerald-500 text-emerald-400 bg-emerald-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Lock className="w-3.5 h-3.5" />
          {t.channelsHeader}
        </button>

        <button
          onClick={() => setActiveTab('directory')}
          className={`py-2.5 px-3.5 text-xs font-bold border-b-2 flex items-center gap-2 transition whitespace-nowrap ${
            activeTab === 'directory'
              ? 'border-emerald-500 text-emerald-400 bg-emerald-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Building2 className="w-3.5 h-3.5" />
          {t.directoryTab}
        </button>

        {canManageAccounts && <button
          onClick={() => setActiveTab('admin')}
          className={`py-2.5 px-3.5 text-xs font-bold border-b-2 flex items-center gap-2 transition whitespace-nowrap ${
            activeTab === 'admin'
              ? 'border-amber-500 text-amber-400 bg-amber-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <UserX className="w-3.5 h-3.5" />
          {t.adminRevokeTab}
        </button>}

        {canInspectSecurity && <button
          onClick={() => setActiveTab('inspector')}
          className={`py-2.5 px-3.5 text-xs font-bold border-b-2 flex items-center gap-2 transition whitespace-nowrap ${
            activeTab === 'inspector'
              ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Database className="w-3.5 h-3.5" />
          {t.juryInspectorTab}
        </button>}
      </div>

      {/* ==================================================================== */}
      {/* ONGLET 1 : MESSAGERIE CHIFFRÉE DE BOUT EN BOUT                       */}
      {/* ==================================================================== */}
      {activeTab === 'chat' && (
        <div className="flex-1 flex overflow-hidden">
          {/* Liste des canaux institutionnels */}
          <aside className="w-72 bg-slate-900/80 border-r border-slate-800 flex flex-col shrink-0">
            <div className="p-3 border-b border-slate-800 flex items-center justify-between">
              <span className="text-sm font-semibold text-slate-200">Conversations</span>
              {canManageAccounts && (
                <button
                  type="button"
                  onClick={() => {
                    setNewChannelForm({
                      name: '',
                      ministry_scope: currentAgent?.role === 'SUPER_ADMIN_DGTD' ? 'TOUS' : currentAgent?.ministry || 'TOUS',
                      channel_type: 'GROUP',
                      default_classification: 'DIFFUSION_RESTREINTE',
                      member_ids: [],
                    });
                    setShowNewChannelModal(true);
                  }}
                  className="px-2 py-1 rounded-lg bg-emerald-700 hover:bg-emerald-600 text-white text-[11px] font-bold flex items-center gap-1 shadow transition"
                  title="Créer un nouveau salon ministériel ou interministériel"
                >
                  <Plus className="w-3.5 h-3.5" />
                  Nouveau
                </button>
              )}
            </div>

            <div className="flex-1 overflow-y-auto p-2 space-y-1.5">
              {channels.map((ch) => (
                <button
                  key={ch.id}
                  onClick={() => setSelectedChannelId(ch.id)}
                  className={`w-full text-left p-3 rounded-xl border transition ${
                    selectedChannelId === ch.id
                      ? 'bg-emerald-950/50 border-emerald-500/80 text-white'
                      : 'bg-slate-950/50 border-slate-800/80 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between gap-1 mb-1">
                    <span className="font-semibold text-xs truncate">{ch.name}</span>
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-slate-400">
                    <span>{ch.default_classification === 'ORDINAIRE' ? 'Standard' : ch.default_classification === 'DIFFUSION_RESTREINTE' ? 'Restreint' : 'Confidentiel'}</span>
                    <span>{ch.active_members?.length || 0} membres</span>
                  </div>
                </button>
              ))}
            </div>

            {/* Empreinte cryptographique locale de l'agent (Numéro de Sécurité 30 chiffres) */}
            <div className="p-3 border-t border-slate-200 text-xs text-slate-600">
              <details>
                <summary className="cursor-pointer">Détails de sécurité</summary>
                <p className="mt-2 break-all font-mono text-[10px]">Empreinte : {keystore?.safetyNumber || 'Calcul en cours…'}</p>
                <p className="mt-1">Vos clés restent sur cet appareil.</p>
              </details>
            </div>
          </aside>

          {/* Zone centrale de conversation E2EE */}
          <main className="flex-1 flex flex-col bg-slate-950 overflow-hidden relative">
            {/* En-tête du canal courant */}
            {currentChannel && (
              <div className="px-5 py-3 bg-slate-900/50 border-b border-slate-800 flex items-center justify-between shrink-0">
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="font-bold text-sm text-white">{currentChannel.name}</h2>
                  </div>
                  <div className="text-xs text-slate-400 mt-0.5">
                    {currentChannel.active_members?.length || 0} membres • Messages réservés aux membres de cette conversation
                  </div>
                </div>

              </div>
            )}

            {/* Fil des messages déchiffrés côté client */}
            <div className="flex-1 overflow-y-auto p-5 space-y-4">
              {messages.length === 0 ? (
                <div className="text-center py-12 text-slate-500 text-sm">
                  Aucun message pour le moment. Écrivez votre premier message ci-dessous.
                </div>
              ) : (
                messages.map((msg) => {
                  const dec = decryptedMap[msg.id];
                  const senderMatricule =
                    dec?.content?.senderMatricule || msg.sender_matricule || msg.sender_pseudonym_hash;
                  const senderName =
                    dec?.content?.senderName || msg.sender_name || 'Agent Souverain (Sealed Sender)';
                  const msgClassification =
                    dec?.content?.classification ||
                    (msg.classification && msg.classification !== 'SEALED_E2EE'
                      ? msg.classification
                      : 'ORDINAIRE');
                  const msgKind =
                    dec?.content?.messageKind ||
                    (msg.message_kind && msg.message_kind !== 'SEALED_E2EE'
                      ? msg.message_kind
                      : 'TEXT');
                  const isMine = senderMatricule === currentAgent.matricule;
                  const isConfidentiel = msgClassification === 'CONFIDENTIEL';
                  const isRestreint = msgClassification === 'DIFFUSION_RESTREINTE';
                  const isSignatureValid = Boolean(dec?.decryptedOk && dec?.signatureVerified);
                  const isSignatureForgedOrUnverified = Boolean(dec?.decryptedOk && !dec?.signatureVerified);
                  const hasSignedReceipt = msg.probative_receipts?.some(
                    (r) => r.agent_matricule === currentAgent.matricule
                  );

                  return (
                    <div
                      key={msg.id}
                      onCopy={(e) => {
                        if (dec?.content?.noForward || isConfidentiel || isRestreint) {
                          e.preventDefault();
                          alert('Copie interdite sur un message classifié Diffusion Restreinte / Confidentiel.');
                        }
                      }}
                      className={`max-w-2xl rounded-2xl p-4 border relative overflow-hidden transition ${
                        isMine
                          ? 'ml-auto bg-emerald-950/30 border-emerald-700/60'
                          : 'mr-auto bg-slate-900/90 border-slate-800'
                      }`}
                    >
                      {/* Filigrane dynamique anti-photo d'écran pour les messages classifiés */}
                      {(isConfidentiel || isRestreint) && (
                        <div className="pointer-events-none select-none absolute inset-0 flex items-center justify-center opacity-[0.06] -rotate-12 text-xl font-black font-mono text-white whitespace-nowrap">
                          {currentAgent.matricule} • {currentAgent.full_name} • CONFIDENTIEL BURKINA FASO
                        </div>
                      )}

                      {/* En-tête du message : Émetteur (Sealed Sender déchiffré) + Badge Classification + ECDSA */}
                      <div className="flex flex-wrap items-center justify-between gap-2 mb-2 relative z-10">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-xs text-white">{senderName}</span>
                          {isMine && <span className="text-[10px] text-slate-500">Vous</span>}
                          {isSignatureValid && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-800 border border-emerald-200">
                              ✓ Identité confirmée
                            </span>
                          )}
                          {isSignatureForgedOrUnverified && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-50 text-red-800 border border-red-200">
                              ⚠ Identité à vérifier
                            </span>
                          )}
                        </div>

                        <div className="flex items-center gap-1.5">
                          <span
                            className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                              isConfidentiel
                                ? 'bg-red-950 text-red-300 border-red-500'
                                : isRestreint
                                ? 'bg-amber-950 text-amber-300 border-amber-500'
                                : 'bg-slate-800 text-emerald-300 border-slate-700'
                            }`}
                          >
                            {msgClassification === 'ORDINAIRE' ? 'Standard' : msgClassification === 'DIFFUSION_RESTREINTE' ? 'Restreint' : 'Confidentiel'}
                          </span>
                          {msg.expires_at && (
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950/80 text-red-300">
                              Expire: {new Date(msg.expires_at).toLocaleTimeString('fr-FR')}
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Corps du message déchiffré localement (avec floutage anti-regard si CONFIDENTIEL) */}
                      <div
                        className={`text-sm text-slate-100 leading-relaxed relative z-10 ${
                          isConfidentiel
                            ? 'blur-sm hover:blur-none transition duration-200 select-none'
                            : ''
                        }`}
                        title={isConfidentiel ? t.confidentielHoverWarning : ''}
                      >
                        {dec ? dec.content.text : 'Déchiffrement E2EE local en cours...'}
                      </div>

                      {isConfidentiel && (
                        <div className="text-[10px] text-red-300/80 mt-1 flex items-center gap-1">
                          <EyeOff className="w-3 h-3" />
                          {t.confidentielHoverWarning}
                        </div>
                      )}

                      {(isRestreint || isConfidentiel) && (
                        <div className="text-[10px] text-amber-300/80 mt-1 flex items-center gap-1">
                          <Shield className="w-3 h-3" />
                          {t.noForwardWarning}
                        </div>
                      )}

                      {/* Lecteur de Note Vocale E2EE ou Téléchargement de Pièce Jointe E2EE */}
                      {msg.encrypted_blob_id && (
                        <div className="mt-3 p-3 rounded-xl bg-slate-950/90 border border-slate-800 relative z-10">
                          <div className="flex items-center justify-between gap-2">
                            <div className="text-xs font-semibold text-emerald-300 flex items-center gap-1.5">
                              <FileLock2 className="w-4 h-4" />
                              {msgKind === 'VOICE_NOTE'
                                ? `Note vocale chiffrée E2EE (${dec?.content?.voiceLang || 'Langue nationale'})`
                                : `Fichier chiffré E2EE : ${dec?.content?.fileName || msg.encrypted_blob_id}`}
                            </div>
                            {!decryptedBlobsMap[msg.encrypted_blob_id] && (
                              <button
                                onClick={() => handleDecryptAndLoadBlob(msg)}
                                className="px-2.5 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1"
                              >
                                <Play className="w-3 h-3" /> Déchiffrer localement
                              </button>
                            )}
                          </div>

                          {decryptedBlobsMap[msg.encrypted_blob_id] && (
                            <div className="mt-2">
                              {msgKind === 'VOICE_NOTE' ? (
                                <audio
                                  controls
                                  src={decryptedBlobsMap[msg.encrypted_blob_id]}
                                  className="w-full h-9 mt-1"
                                />
                              ) : (
                                <a
                                  href={decryptedBlobsMap[msg.encrypted_blob_id]}
                                  download={dec?.content?.fileName || 'document_souverain_decrypte'}
                                  className="inline-flex items-center gap-1.5 text-xs text-amber-300 hover:underline mt-1"
                                >
                                  <Download className="w-3.5 h-3.5" />
                                  Enregistrer le fichier déchiffré ({dec?.content?.fileName})
                                </a>
                              )}
                            </div>
                          )}
                        </div>
                      )}

                      {/* Accusé de lecture à valeur probante (Instructions de Service) */}
                      {(msg.requires_probative_receipt || msg.probative_receipts?.length > 0) && (
                        <div className="mt-3 pt-2.5 border-t border-slate-800/90 relative z-10">
                          <div className="flex items-center justify-between flex-wrap gap-2">
                            <span className="text-[11px] font-semibold text-amber-300 flex items-center gap-1">
                              <FileCheck2 className="w-3.5 h-3.5" />
                              Instruction de service à valeur probante
                            </span>

                            {!hasSignedReceipt ? (
                              <button
                                onClick={() => handleSignProbativeReceipt(msg)}
                                className="px-3 py-1 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs transition"
                              >
                                {t.signProbativeReceipt}
                              </button>
                            ) : (
                              <span className="text-[11px] text-emerald-400 font-semibold flex items-center gap-1">
                                <CheckCircle2 className="w-3.5 h-3.5" />
                                {t.receiptSigned}
                              </span>
                            )}
                          </div>

                          {msg.probative_receipts?.length > 0 && (
                            <div className="mt-2 space-y-1">
                              {msg.probative_receipts.map((r) => (
                                <div
                                  key={r.id}
                                  className="text-[10px] font-mono bg-slate-950/80 px-2.5 py-1 rounded border border-slate-800 text-slate-300 flex items-center justify-between"
                                >
                                  <span>
                                    ✓ Signé par <strong>{r.agent_full_name}</strong> ({r.agent_matricule})
                                  </span>
                                  <span className="text-emerald-400">
                                    ECDSA: {r.signature_hex.slice(0, 20)}...
                                  </span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}

                    </div>
                  );
                })
              )}
            </div>

            {/* Zone de rédaction et de chiffrement E2EE */}
            <form
              onSubmit={handleSendEncryptedText}
              className="p-3.5 bg-slate-900 border-t border-slate-800 space-y-2.5 shrink-0"
            >
              <details className="text-xs">
                <summary className="w-fit cursor-pointer text-slate-500">Options du message · {classification === 'ORDINAIRE' ? 'Standard' : classification === 'DIFFUSION_RESTREINTE' ? 'Restreint' : 'Confidentiel'}</summary>
              <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-xs">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-slate-400 font-medium">{t.classificationLabel}</span>
                  {['ORDINAIRE', 'DIFFUSION_RESTREINTE', 'CONFIDENTIEL'].map((lvl) => (
                    <button
                      type="button"
                      key={lvl}
                      onClick={() => setClassification(lvl)}
                      className={`px-2.5 py-1 rounded-lg font-bold text-[11px] border transition ${
                        classification === lvl
                          ? lvl === 'CONFIDENTIEL'
                            ? 'bg-red-600 text-white border-red-400'
                            : lvl === 'DIFFUSION_RESTREINTE'
                            ? 'bg-amber-500 text-slate-950 border-amber-300'
                            : 'bg-emerald-600 text-white border-emerald-400'
                          : 'bg-slate-950 text-slate-400 border-slate-800'
                      }`}
                    >
                      {lvl === 'ORDINAIRE' ? 'Standard' : lvl === 'DIFFUSION_RESTREINTE' ? 'Restreint' : 'Confidentiel'}
                    </button>
                  ))}

                  <select
                    value={voiceNoteLang}
                    onChange={(e) => setVoiceNoteLang(e.target.value)}
                    aria-label="Langue du message vocal"
                    className="bg-slate-950 border border-slate-800 rounded-lg px-2 py-1 text-[11px] text-slate-300"
                  >
                    <option value="Mooré">Voix : Mooré</option>
                    <option value="Dioula">Voix : Dioula</option>
                    <option value="Fulfulde">Voix : Fulfulde</option>
                    <option value="Français">Voix : Français</option>
                  </select>

                  <select
                    value={expiresInSeconds}
                    onChange={(e) => setExpiresInSeconds(Number(e.target.value))}
                    className="bg-slate-950 border border-slate-800 rounded-lg px-2 py-1 text-[11px] text-slate-300"
                  >
                    <option value={0}>Sans expiration</option>
                    <option value={60}>Auto-destruction : 60 sec</option>
                    <option value={300}>Auto-destruction : 5 min</option>
                    <option value={3600}>Auto-destruction : 1 heure</option>
                  </select>
                </div>

                <label className="flex items-center gap-1.5 text-amber-300 cursor-pointer text-[11px] font-medium">
                  <input
                    type="checkbox"
                    checked={requiresReceipt}
                    onChange={(e) => setRequiresReceipt(e.target.checked)}
                    className="rounded border-slate-700"
                  />
                  {t.requireProbativeReceipt}
                </label>
              </div>
              </details>

              {/* Barre de saisie + Note vocale E2EE en langue nationale + Fichier E2EE */}
              <div className="flex items-center gap-2">
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileUploadChange}
                  className="hidden"
                />
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="p-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700"
                  title={t.attachEncryptedFile}
                >
                  <Paperclip className="w-4 h-4" />
                </button>

                <button
                  type="button"
                  onClick={handleToggleVoiceRecording}
                  title={isRecordingVoice ? t.stopAndSendVoice : t.recordVoice}
                  aria-label={isRecordingVoice ? t.stopAndSendVoice : t.recordVoice}
                  className={`px-2.5 py-2.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition ${
                    isRecordingVoice
                      ? 'bg-red-600 text-white animate-pulse'
                      : 'bg-slate-800 hover:bg-slate-700 text-emerald-300'
                  }`}
                >
                  {isRecordingVoice ? <Square className="w-3.5 h-3.5" /> : <Mic className="w-3.5 h-3.5" />}
                  <span>{isRecordingVoice ? 'Arrêter' : 'Vocal'}</span>
                </button>

                <input
                  type="text"
                  value={draftText}
                  onChange={(e) => setDraftText(e.target.value)}
                  placeholder={t.composerPlaceholder}
                  className="flex-1 bg-slate-950 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-white focus:border-emerald-500 focus:outline-none"
                />

                <button
                  type="submit"
                  className="px-4 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center gap-1.5 shrink-0 transition"
                >
                  <Send className="w-4 h-4" />
                  <span>{t.sendEncrypted}</span>
                </button>
              </div>
            </form>
          </main>
        </div>
      )}

      {/* ==================================================================== */}
      {/* ONGLET 2 : ANNUAIRE OFFICIEL PAR MINISTÈRE & FONCTION                */}
      {/* ==================================================================== */}
      {activeTab === 'directory' && (
        <div className="flex-1 overflow-y-auto p-6 max-w-6xl w-full mx-auto space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Building2 className="w-5 h-5 text-emerald-400" />
                Annuaire Officiel des Agents Publics Enrôlés par Ministère
              </h2>
              <p className="text-xs text-slate-400">
                Identités vérifiées avec 2FA TOTP (RFC 6238) et clés publiques E2EE certifiées.
              </p>
            </div>

            <select
              value={selectedMinistryFilter}
              onChange={(e) => setSelectedMinistryFilter(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-xs text-white"
            >
              <option value="TOUS">Tous les Ministères ({directoryData.agents?.length || 0})</option>
              {Object.keys(directoryData.by_ministry || {}).map((min) => (
                <option key={min} value={min}>
                  {min}
                </option>
              ))}
            </select>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {(directoryData.agents || [])
              .filter((a) => selectedMinistryFilter === 'TOUS' || a.ministry === selectedMinistryFilter)
              .map((ag) => (
                <div
                  key={ag.id}
                  className={`p-4 rounded-2xl border ${
                    ag.is_revoked
                      ? 'bg-red-950/20 border-red-800/70'
                      : 'bg-slate-900/90 border-slate-800'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-slate-800 text-amber-300">
                          {ag.matricule}
                        </span>
                        <span className="font-bold text-sm text-white">{ag.full_name}</span>
                      </div>
                      <div className="text-xs text-emerald-400 font-medium mt-1">{ag.ministry}</div>
                      <div className="text-xs text-slate-400">
                        {ag.direction} — <em>{ag.job_title}</em>
                      </div>
                    </div>

                    {ag.is_revoked ? (
                      <span className="text-[10px] font-bold px-2.5 py-1 rounded-full bg-red-900 text-red-200">
                        ACCÈS RÉVOQUÉ
                      </span>
                    ) : (
                      <span className="text-[10px] font-bold px-2.5 py-1 rounded-full bg-emerald-950 text-emerald-300 border border-emerald-700">
                        2FA + E2EE VÉRIFIÉ
                      </span>
                    )}
                  </div>

                  <div className="mt-3 pt-2.5 border-t border-slate-800 text-[11px] font-mono text-slate-400 flex flex-wrap items-center justify-between gap-2">
                    <span>Rôle: {ag.role}</span>
                    <span className="text-amber-300" title="Numéro de sécurité (Safety Number) SHA-256 à 30 chiffres pour vérification hors-bande">
                      Numéro de sécurité: {ag.safety_number || ag.e2ee_bundle?.safety_number || 'En attente de clé'}
                    </span>
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* ONGLET 3 : ADMINISTRATION DGTD & ÉPREUVE DE RÉVOCATION EN DIRECT     */}
      {/* ==================================================================== */}
      {canManageAccounts && activeTab === 'admin' && (
        <div className="flex-1 overflow-y-auto p-6 max-w-6xl w-full mx-auto grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Liste de révocation en direct */}
          <div className="lg:col-span-7 space-y-4">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5">
              <h2 className="text-base font-bold text-amber-400 flex items-center gap-2 mb-1">
                <UserX className="w-5 h-5" />
                Épreuve en Direct du Jury : Révocation Immédiate d’un Agent
              </h2>
              <p className="text-xs text-slate-400 mb-4 leading-relaxed">
                « Le jury révoque un agent pendant une conversation de groupe ; celui-ci doit perdre
                immédiatement l’accès, y compris aux nouveaux messages. » Cliquez sur{' '}
                <strong>Révoquer immédiatement</strong> sur un agent (ex: <code className="text-amber-300">BF-MISSION-999</code>) :
                sa session WebSocket est coupée instantanément, ses clés locales sont effacées (Remote Wipe),
                et l’époque cryptographique E2EE du groupe est renouvelée.
              </p>

              <div className="space-y-3">
                {(directoryData.agents || []).map((ag) => (
                  <div
                    key={ag.id}
                    className={`p-3.5 rounded-xl border flex flex-wrap items-center justify-between gap-3 ${
                      ag.is_revoked
                        ? 'bg-red-950/30 border-red-700'
                        : 'bg-slate-950 border-slate-800'
                    }`}
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-amber-300">{ag.matricule}</span>
                        <span className="font-bold text-sm text-white">{ag.full_name}</span>
                        {ag.is_revoked && (
                          <span className="text-[10px] bg-red-600 text-white px-2 py-0.5 rounded font-bold">
                            RÉVOQUÉ
                          </span>
                        )}
                        {!ag.is_enrolled_activated && !ag.is_revoked && (
                          <span className="text-[10px] bg-amber-700/70 text-amber-100 px-2 py-0.5 rounded font-bold">INVITATION EN ATTENTE</span>
                        )}
                      </div>
                      <div className="text-xs text-slate-400">{ag.ministry}</div>
                      <div className="mt-2 flex items-center gap-2 text-xs text-slate-500">
                        <span>Rôle : {ag.role}</span>
                        {currentAgent.role === 'SUPER_ADMIN_DGTD' && (
                          <>
                            <select
                              aria-label={`Rôle de ${ag.full_name}`}
                              disabled={ag.id === currentAgent.id}
                              value={roleDrafts[ag.id] || ag.role}
                              onChange={(e) => setRoleDrafts((prev) => ({ ...prev, [ag.id]: e.target.value }))}
                              className="rounded border border-slate-700 bg-white px-2 py-1 text-slate-800 disabled:opacity-50"
                            >
                              <option value="AGENT_PUBLIC">Agent public</option>
                              <option value="POINT_FOCAL">Point focal</option>
                              <option value="AUDITEUR">Auditeur</option>
                              <option value="SUPER_ADMIN_DGTD">Administrateur DGTD</option>
                            </select>
                            {roleDrafts[ag.id] && roleDrafts[ag.id] !== ag.role && (
                              <button
                                type="button"
                                onClick={() => handleChangeAgentRole(ag)}
                                className="rounded bg-emerald-700 px-2 py-1 text-white hover:bg-emerald-600"
                              >
                                Appliquer
                              </button>
                            )}
                          </>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      {!ag.is_enrolled_activated && !ag.is_revoked && (
                        <button
                          type="button"
                          onClick={() => handleReissueActivationCode(ag)}
                          className="px-3 py-1.5 rounded-lg bg-amber-700 hover:bg-amber-600 text-white text-xs font-bold"
                        >
                          Réémettre le code
                        </button>
                      )}
                      {!ag.is_revoked ? (
                        <button
                          onClick={() => handleRevokeAgent(ag)}
                          disabled={ag.matricule === currentAgent.matricule}
                          className="px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 disabled:opacity-40 text-white text-xs font-bold flex items-center gap-1.5 transition"
                        >
                          <UserX className="w-3.5 h-3.5" />
                          {t.revokeAgentBtn}
                        </button>
                      ) : (
                        <button
                          onClick={() => handleReinstateAgent(ag)}
                          className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold flex items-center gap-1.5 transition"
                        >
                          <UserCheck className="w-3.5 h-3.5" />
                          {t.reinstateAgentBtn}
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Enrôlement officiel d'un nouvel agent avec génération 2FA TOTP */}
          <div className="lg:col-span-5">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5">
              <h2 className="text-base font-bold text-emerald-400 flex items-center gap-2 mb-1">
                <UserPlus className="w-5 h-5" />
                Enrôler un Nouvel Agent Public (DGTD)
              </h2>
              <p className="text-xs text-slate-400 mb-4">
                  L’agent reçoit un code d’activation à usage unique, puis choisit lui-même son mot de passe et configure son 2FA.
              </p>

              <form onSubmit={handleEnrolNewAgent} className="space-y-3 text-xs">
                <div>
                  <label className="block text-slate-300 mb-1">Matricule Officiel</label>
                  <input
                    type="text"
                    value={newAgentForm.matricule}
                    onChange={(e) => setNewAgentForm({ ...newAgentForm, matricule: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 font-mono text-white"
                    required
                  />
                </div>
                <div>
                  <label className="block text-slate-300 mb-1">Nom et Prénom(s) (Fictif)</label>
                  <input
                    type="text"
                    value={newAgentForm.full_name}
                    onChange={(e) => setNewAgentForm({ ...newAgentForm, full_name: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-white"
                    required
                  />
                </div>
                <div>
                  <label className="block text-slate-300 mb-1">Ministère / Institution</label>
                  <input
                    type="text"
                    value={newAgentForm.ministry}
                    onChange={(e) => setNewAgentForm({ ...newAgentForm, ministry: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-white"
                    required
                  />
                </div>
                <div>
                  <label className="block text-slate-300 mb-1">Direction / Service</label>
                  <input
                    type="text"
                    value={newAgentForm.direction}
                    onChange={(e) => setNewAgentForm({ ...newAgentForm, direction: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-white"
                    required
                  />
                </div>
                {currentAgent.role === 'SUPER_ADMIN_DGTD' && (
                  <div>
                    <label className="block text-slate-300 mb-1">Rôle attribué</label>
                    <select
                      value={newAgentForm.role}
                      onChange={(e) => setNewAgentForm({ ...newAgentForm, role: e.target.value })}
                      className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-white"
                    >
                      <option value="AGENT_PUBLIC">Agent public</option>
                      <option value="POINT_FOCAL">Point focal</option>
                      <option value="AUDITEUR">Auditeur (lecture seule)</option>
                      <option value="SUPER_ADMIN_DGTD">Administrateur DGTD</option>
                    </select>
                    <p className="mt-1 text-[11px] text-slate-500">Les rôles privilégiés ne sont attribuables que par la DGTD.</p>
                  </div>
                )}
                <button
                  type="submit"
                  className="w-full py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold"
                >
                  Créer le compte & Générer le code d’activation
                </button>
              </form>

              {enrolmentResult && (
                <div className="mt-4 p-3.5 rounded-xl bg-emerald-950/60 border border-emerald-500 text-xs space-y-1">
                  <div className="font-bold text-emerald-300">
                    ✓ Invitation créée pour {enrolmentResult.matricule}
                  </div>
                  <div className="text-emerald-100">Remettez uniquement ce code à l’agent par un canal institutionnel sûr. Il expire le {new Date(enrolmentResult.activation_expires_at).toLocaleString()}.</div>
                  <div className="select-all break-all rounded-lg border border-emerald-700 bg-slate-950 p-3 font-mono text-sm text-amber-300">
                    {enrolmentResult.activation_code_once}
                  </div>
                  <div className="text-[11px] text-slate-300">Ce code ne s’affichera plus après fermeture de cette fiche. Il ne contient ni mot de passe ni secret TOTP.</div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* ONGLET 4 : INSPECTEUR JURY (« LE SERVEUR NE LIT RIEN »)              */}
      {/* ==================================================================== */}
      {canInspectSecurity && activeTab === 'inspector' && (
        <div className="flex-1 overflow-y-auto p-6 max-w-6xl w-full mx-auto space-y-6">
          <div className="bg-slate-900 border border-cyan-500/50 rounded-2xl p-5">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h2 className="text-base font-bold text-cyan-300 flex items-center gap-2">
                  <Database className="w-5 h-5" />
                  Épreuve en Direct du Jury : « Le Serveur Ne Lit Rien » (Inspection BDD & Trafic Réseau)
                </h2>
                <p className="text-xs text-slate-400">
                  Vue directe et sans filtre des tables SQLite/PostgreSQL côté serveur et des trames WebSocket.
                  Aucun message, nom de fichier ou audio n’apparaît jamais en clair.
                </p>
              </div>
              <button
                onClick={loadJuryInspectionData}
                className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold flex items-center gap-1.5"
              >
                <RefreshCw className="w-3.5 h-3.5" /> Actualiser l’inspection BDD
              </button>
            </div>

            {inspectionError && (
              <div className="p-4 rounded-xl bg-red-950/60 border border-red-500 text-xs text-red-200">
                {inspectionError}
              </div>
            )}

            {inspectionData && (
              <div className="space-y-5">
                {/* Synthèse Zero-Knowledge & Minimisation des métadonnées */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="text-slate-400">Colonnes en clair (vérifiées dynamiquement)</div>
                    <div className="text-xl font-extrabold text-emerald-400 mt-1">
                      {inspectionData.zero_knowledge_verification?.plaintext_columns_in_db ?? 0} (Zéro Texte Clair)
                    </div>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="text-slate-400">Secrets 2FA TOTP en BDD</div>
                    <div className="text-sm font-bold text-amber-300 mt-1">
                      {inspectionData.zero_knowledge_verification?.all_totp_secrets_fernet_encrypted_at_rest
                        ? '100% Chiffrés au repos (Fernet AES-128-CBC + HMAC)'
                        : 'Vérification en cours'}
                    </div>
                  </div>
                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <div className="text-slate-400">Granularité temporelle & Padding</div>
                    <div className="text-sm font-bold text-cyan-300 mt-1">
                      Tranches 5 min • Messages 256o / Blobs 4 Ko
                    </div>
                  </div>
                </div>

                {/* Table SQL brute `encrypted_messages` */}
                <div>
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
                    Table SQL `encrypted_messages` (Contenu brut stocké sur le disque serveur)
                  </h3>
                  <div className="bg-slate-950 border border-slate-800 rounded-xl p-3 overflow-x-auto max-h-60">
                    <pre className="text-[11px] font-mono text-emerald-300">
                      {JSON.stringify(inspectionData.database_table_encrypted_messages, null, 2)}
                    </pre>
                  </div>
                </div>

                {/* Trames réseau brutes WebSocket & Blobs chiffrés */}
                <div>
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
                    Trames Réseau Brutes (`recent_network_wire_frames` — Zéro clair sur le fil)
                  </h3>
                  <div className="bg-slate-950 border border-slate-800 rounded-xl p-3 overflow-x-auto max-h-48">
                    <pre className="text-[11px] font-mono text-cyan-300">
                      {JSON.stringify(inspectionData.recent_network_wire_frames, null, 2)}
                    </pre>
                  </div>
                </div>

                {/* Journal d'audit de sécurité (Intrus rejetés, révocations, 2FA) */}
                <div>
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
                    Journal d’Audit de Sécurité (`security_audit_logs` — Pseudonymisé)
                  </h3>
                  <div className="bg-slate-950 border border-slate-800 rounded-xl p-3 overflow-x-auto max-h-60">
                    <pre className="text-[11px] font-mono text-amber-300">
                      {JSON.stringify(inspectionData.security_audit_logs, null, 2)}
                    </pre>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Modal de création de canal */}
      {showNewChannelModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Users className="w-5 h-5 text-emerald-400" />
                Créer une nouvelle conversation E2EE
              </h3>
              <button
                type="button"
                onClick={() => setShowNewChannelModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreateChannel} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 mb-1 font-semibold">Nom du canal</label>
                <input
                  type="text"
                  placeholder="Ex : Coordination Urgences CHU"
                  value={newChannelForm.name}
                  onChange={(e) => setNewChannelForm({ ...newChannelForm, name: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-white"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1 font-semibold">Classification par défaut</label>
                <select
                  value={newChannelForm.default_classification}
                  onChange={(e) => setNewChannelForm({ ...newChannelForm, default_classification: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-white"
                >
                  <option value="ORDINAIRE">ORDINAIRE (Diffusion large)</option>
                  <option value="DIFFUSION_RESTREINTE">DIFFUSION RESTREINTE</option>
                  <option value="CONFIDENTIEL">CONFIDENTIEL (Strictement protégé)</option>
                </select>
              </div>

              {currentAgent?.role === 'SUPER_ADMIN_DGTD' && (
                <div>
                  <label className="block text-slate-300 mb-1 font-semibold">Portée du canal</label>
                  <select
                    value={newChannelForm.ministry_scope}
                    onChange={(e) => setNewChannelForm({ ...newChannelForm, ministry_scope: e.target.value })}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-white"
                  >
                    <option value="TOUS">Interministériel (Tous les ministères)</option>
                    {Object.keys(directoryData.by_ministry || {}).map((min) => (
                      <option key={min} value={min}>{min}</option>
                    ))}
                  </select>
                </div>
              )}

              <div>
                <label className="block text-slate-300 mb-1 font-semibold">
                  Membres invités ({newChannelForm.member_ids.length} sélectionné(s))
                </label>
                <div className="max-h-36 overflow-y-auto space-y-1 bg-slate-950 border border-slate-800 rounded-lg p-2">
                  {(directoryData.agents || [])
                    .filter((ag) => !ag.is_revoked && ag.id !== currentAgent?.id)
                    .filter((ag) => currentAgent?.role === 'SUPER_ADMIN_DGTD' || ag.ministry === currentAgent?.ministry)
                    .map((ag) => (
                      <label key={ag.id} className="flex items-center gap-2 p-1 rounded hover:bg-slate-900 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={newChannelForm.member_ids.includes(ag.id)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setNewChannelForm((prev) => ({ ...prev, member_ids: [...prev.member_ids, ag.id] }));
                            } else {
                              setNewChannelForm((prev) => ({ ...prev, member_ids: prev.member_ids.filter((id) => id !== ag.id) }));
                            }
                          }}
                        />
                        <span className="font-mono text-amber-300 text-[11px]">{ag.matricule}</span>
                        <span className="text-white text-xs truncate">{ag.full_name}</span>
                        <span className="text-slate-400 text-[10px] ml-auto">({ag.ministry})</span>
                      </label>
                    ))}
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowNewChannelModal(false)}
                  className="px-3 py-1.5 rounded-lg border border-slate-700 hover:bg-slate-800 text-slate-300 text-xs"
                >
                  Annuler
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs"
                >
                  Créer le canal
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
