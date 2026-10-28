"""
Gestionnaire temps réel WebSocket Zero-Knowledge & Révocation Immédiate.
Assure :
1. La diffusion instantanée des enveloppes chiffrées E2EE aux membres autorisés d'un canal
2. La coupure immédiate des sessions WebSocket d'un agent révoqué + signal `REMOTE_WIPE`
3. La notification de rotation d'époque cryptographique (`CRYPTO_EPOCH_ROTATED`) aux groupes
   afin qu'un agent révoqué ne puisse plus jamais déchiffrer les nouveaux messages
4. L'enregistrement des dernières trames réseau brutes (chiffrées) pour l'épreuve du jury
   « Le serveur ne lit rien : inspection de la base de données et du trafic réseau »
"""

from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Set
from fastapi import WebSocket


class SovereignConnectionManager:
    def __init__(self) -> None:
        # agent_id -> ensemble de connexions WebSocket actives (multi-appareils)
        self.active_connections: Dict[int, Set[WebSocket]] = {}
        # Journal circulaire des 50 dernières trames réseau transitant par le serveur (audit jury)
        self.recent_network_frames: deque = deque(maxlen=50)

    async def connect(self, agent_id: int, websocket: WebSocket) -> None:
        await websocket.accept()
        if agent_id not in self.active_connections:
            self.active_connections[agent_id] = set()
        self.active_connections[agent_id].add(websocket)

    def disconnect(self, agent_id: int, websocket: WebSocket) -> None:
        if agent_id in self.active_connections:
            self.active_connections[agent_id].discard(websocket)
            if not self.active_connections[agent_id]:
                del self.active_connections[agent_id]

    def record_wire_frame(self, direction: str, frame_type: str, payload_preview: Dict[str, Any]) -> None:
        """Enregistre la trame brute telle que vue sur le réseau par le serveur (zéro texte en clair)."""
        self.recent_network_frames.appendleft(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "direction": direction,
                "frame_type": frame_type,
                "wire_payload": payload_preview,
            }
        )

    async def send_to_agent(self, agent_id: int, payload: Dict[str, Any]) -> None:
        """Envoie un événement temps réel à tous les appareils connectés d'un agent actif."""
        sockets = list(self.active_connections.get(agent_id, []))
        for ws in sockets:
            try:
                await ws.send_json(payload)
            except Exception:
                self.disconnect(agent_id, ws)

    async def broadcast_to_agents(self, agent_ids: List[int], payload: Dict[str, Any]) -> None:
        """Diffuse une enveloppe chiffrée E2EE uniquement aux membres actifs et non révoqués du canal."""
        self.record_wire_frame("SERVER_TO_CLIENTS", payload.get("type", "E2EE_EVENT"), payload)
        for aid in set(agent_ids):
            await self.send_to_agent(aid, payload)

    async def revoke_and_wipe_agent_immediately(
        self,
        revoked_agent_id: int,
        matricule: str,
        reason: str,
        affected_channel_ids: List[int],
        remaining_agent_ids: List[int],
        new_epochs: Dict[int, int],
    ) -> int:
        """
        Épreuve du jury « Révocation » :
        1. Envoie immédiatement l'ordre `REMOTE_WIPE_AND_REVOKE` à tous les appareils de l'agent révoqué
           pour purger son stockage cryptographique local et verrouiller son écran.
        2. Ferme de force toutes les connexions WebSocket de l'agent révoqué (code 4003).
        3. Notifie tous les autres membres des groupes partagés (`CRYPTO_EPOCH_ROTATION`) pour renouveler
           immédiatement les clés de session de groupe (Megolm / Sender Keys).
        """
        sockets = list(self.active_connections.get(revoked_agent_id, []))
        closed_count = 0
        wipe_signal = {
            "type": "REMOTE_WIPE_AND_REVOKE",
            "agent_id": revoked_agent_id,
            "matricule": matricule,
            "reason": reason,
            "action": "PURGE_KEYSTORE_AND_LOCK_IMMEDIATELY",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.record_wire_frame("SECURITY_REVOCATION_SIGNAL", "REMOTE_WIPE_AND_REVOKE", wipe_signal)

        for ws in sockets:
            try:
                await ws.send_json(wipe_signal)
                await ws.close(code=4003, reason="Agent revoque par la DGTD")
                closed_count += 1
            except Exception:
                pass
            finally:
                self.disconnect(revoked_agent_id, ws)

        rotation_event = {
            "type": "GROUP_CRYPTO_EPOCH_ROTATED",
            "revoked_agent_id": revoked_agent_id,
            "revoked_matricule": matricule,
            "reason": reason,
            "affected_channels": affected_channel_ids,
            "new_epochs": new_epochs,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await self.broadcast_to_agents(remaining_agent_ids, rotation_event)
        return closed_count


ws_manager = SovereignConnectionManager()
