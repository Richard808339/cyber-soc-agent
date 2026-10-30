# Faits mesurés — SOC Wazuh KOFFI

Chaque ligne est une mesure, pas une inférence. Format : fait · valeur · horodatage.
Écraser une valeur périmée plutôt que d'en garder deux.

**Base de temps.** `Z` = UTC lu dans WSL (même horloge que le manager). `locale` = lecture faite
depuis Windows via PowerShell, dont le décalage avec UTC n'a pas été vérifié sur cette machine —
ne pas fusionner les deux bases dans un calcul de durée.

## Plateforme

| Fait | Valeur | Mesuré le |
|---|---|---|
| Distribution WSL du SOC | `wazuh` (Ubuntu 24.04.5 LTS) | 2026-10-29 06:20Z |
| Version | Wazuh 4.14.9, images `wazuh/wazuh-{manager,indexer,dashboard}:4.14.9` | 2026-10-29 06:20Z |
| Mode | single-node (clustering désactivé, c'est le design) | 2026-10-28 23:45Z |
| Compose | `/opt/wazuh-docker/single-node/docker-compose.yml` | 2026-10-28 23:45Z |
| État indexer | green, 1 nœud, 23 shards | 2026-10-29 06:20Z |
| Mémoire d'alertes | 2 index : 2026.10.28 = 1494 docs, 2026.10.29 = 45 docs | 2026-10-29 06:20Z |
| Exposition | 443/9200/55000/1514/1515/514udp → relayés sur localhost Windows uniquement | 2026-10-28 20:10Z |

## Agents

| ID | Nom | OS | Statut | Inventaire syscollector |
|---|---|---|---|---|
| 000 | wazuh.manager | Amazon Linux 2023 (conteneur) | active | oui |
| 002 | zbook-hp | Windows 11 Pro 10.0.26300.9711 (le poste) | active | **non** |

- Total : 2 agents. Aucun agent dans `kali-linux`.
- L'ID 001 a existé puis a été supprimé le 2026-10-28 à 23:48:45Z (clé perdue, boucle
  d'enrôlement). L'agent est revenu en 002 à 23:49:02Z. Filtrer sur `agent.name`.
- Tous les agents apparaissent en `127.0.0.1` : c'est le relais WSL.

## Détection

| Fait | Valeur | Mesuré le |
|---|---|---|
| Alertes 24 h | 1547 — niveaux 9:7, 7:759, 5:64, 4:12, 3:705 | 2026-10-29 06:20Z |
| Alertes niveau ≥ 10 sur 7 j | 0 | 2026-10-28 23:59Z |
| Bruit | ~94 % en niveau 3 et 7 (Logon Success, Software protection, System error) | 2026-10-29 06:20Z |
| SCA | CIS Windows 11 Benchmark : score < 30 % | 2026-10-28 23:59Z |
| Vulnérabilités | `wazuh-states-vulnerabilities-*` : 1 doc (le manager) | 2026-10-28 23:59Z |
| Flux CVE | `content-updater` en échec : `Timeout was reached` | 2026-10-28 23:05Z |

## Fragilité structurelle (constatée, non corrigée)

Le SOC **ne survit pas à un redémarrage de la distribution WSL**. `init` est l'init WSL
(pas de systemd), `dockerd` n'est pas démarré automatiquement. Le 2026-10-29, la stack était
arrêtée (`/var/run/docker.sock` absent) alors que les volumes étaient intacts.

Remise en route qui fonctionne (root dans la distro, `sudo` absent) :

```sh
nohup dockerd >/tmp/dockerd.log 2>&1 &
# attendre /var/run/docker.sock
cd /opt/wazuh-docker/single-node && docker compose up -d
# indexer green en ~5 s côté health, API 200 après ~1 min
```

Les données sont conservées (volumes `single-node_wazuh-indexer-data` etc.) : l'historique
d'alertes survit, la disponibilité non.

## Poste KOFFI (Windows 11 Pro build 26300)

| Fait | Valeur | Mesuré le |
|---|---|---|
| Defender | temps réel + comportemental actifs, signatures 1.463.8.0, 0 jour | 2026-10-28 ~23:47Z |
| Règles ASR / PUA / Network Protection | 0 / désactivé / désactivé | 2026-10-28 ~20:02 locale |
| Scan complet | jamais enregistré (rapide : 25/10 11:21) | 2026-10-28 ~20:02 locale |
| Pare-feu | 3 profils actifs, 166 règles entrantes autorisées | 2026-10-28 ~20:02 locale |
| RDP / WinRM / SMBv1 | désactivé / arrêté / désactivé | 2026-10-28 ~20:02 locale |
| Signature SMB | RequireSecuritySignature = True (était False à 20:02 locale, changement non tracé) | 2026-10-28 ~23:10Z |
| AnyDesk | en écoute 0.0.0.0:7070, non bloqué | 2026-10-29 06:20Z |
| NetBIOS 139 | ouvert sur 192.168.1.149, 192.168.174.1, 192.168.75.1, 172.23.96.1 | 2026-10-29 06:20Z |
| Comptes admin locaux | Administrateur, HP, kouas (MicrosoftAccount) | 2026-10-28 ~20:02 locale |
| BitLocker / TPM / Secure Boot | non vérifiés (élévation refusée deux fois) | — |
