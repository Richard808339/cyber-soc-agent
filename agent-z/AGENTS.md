# Contexte du projet — Cyber SOC KOFFI

Lu avant toute tâche dans ce dossier. Décrit où sont les choses, pas ce qu'il faut penser.

## Topologie réelle

```
Windows 11 Pro build 26300 (hôte "KOFFI")
├─ Agent Wazuh (WazuhSvc) ──► localhost:1514/1515 (relais WSL)
└─ WSL
   ├─ kali-linux            (aucun agent Wazuh)
   └─ wazuh (Ubuntu 24.04)  docker compose /opt/wazuh-docker/single-node
      ├─ single-node-wazuh.manager-1   wazuh/wazuh-manager:4.14.9   1514-1515, 55000, 514/udp
      ├─ single-node-wazuh.indexer-1   wazuh/wazuh-indexer:4.14.9   9200
      └─ single-node-wazuh.dashboard-1 wazuh/wazuh-dashboard:4.14.9 443→5601
```

Les ports ne sont relayés que sur localhost côté Windows : le SOC n'est pas joignable depuis
le LAN. Ne pas le présenter comme une exposition réseau.

## Chemins utiles

| Quoi | Où |
|---|---|
| Bilans produits | `Documents\security\Bilan_SOC_*.txt` |
| Orchestrateur | `Documents\security\orchestrateur\` |
| Faits mesurés | `Documents\security\agent-z\knowledge\soc-facts.md` |
| Journal d'exécution | `Documents\security\agent-z\logs\` |
| Script de remédiation (non exécuté) | `Documents\security\soc_fix_audit.ps1` |
| Compose files | WSL `wazuh` : `/opt/wazuh-docker/{single-node,multi-node,wazuh-agent}/` |
| Config Hermes | `C:\Users\HP\AppData\Local\hermes\` (config.yaml, .env, skills/, memories/, logs/) |

## Règles de lecture des données

- L'agent 000 (`wazuh.manager`) est le SOC qui se regarde lui-même. Ne jamais le compter comme
  un actif surveillé.
- Les agents voient tous `127.0.0.1` : c'est le relais WSL, pas une information de localisation.
  Lire `os` et `registerIP` avant de conclure quoi que ce soit.
- L'ID d'agent peut changer (réenrôlement). Filtrer sur `agent.name`, jamais sur `agent.id`.
- Un seul index `wazuh-alerts-4.x-<date>` = le SOC n'a qu'un jour de mémoire.
- Heures : les données Wazuh sont en UTC ; l'hôte affiche l'heure locale. Comparer en UTC.

## Pièges déjà rencontrés

- `GET /agents?...&status=all` et tout `select` d'un champ inexistant renvoient
  `total_affected_items: null` sans erreur.
- `/agents/<id>/stats` et `/daemons-stats` renvoient 404 en 4.14.x.
- Scripts `.sh` écrits depuis Windows : convertir les CRLF (`tr -d '\r'`) avant exécution.
- `sudo` absent dans la distribution : utiliser `docker` directement (appartenance au groupe).
