# Cyber SOC — agent KOFFI

Agent de sécurité défensif pour un poste Windows 11 et le stack Wazuh 4.14.9 qui tourne
dans WSL. Le dépôt contient l'agent, sa spécification, ses connaissances et ses preuves.

## Contenu

| Chemin | Rôle |
|---|---|
| `orchestrateur/orchestrator.py` | route une demande vers l'agent cyber / builder / research |
| `orchestrateur/agents/cyber_agent.py` | interroge réellement l'API Wazuh via WSL |
| `orchestrateur/agents/builder_agent.py` | écrit un squelette de script, sans faux succès |
| `orchestrateur/agents/research_agent.py` | recherche lexicale dans les documents locaux |
| `agent-z/AGENT.md` | purpose, mission, goal, stop condition, validation, evidence |
| `agent-z/AGENTS.md` | topologie, chemins, règles de lecture, pièges |
| `agent-z/knowledge/soc-facts.md` | faits mesurés, avec horodatage et base de temps |
| `agent-z/FICHE-AGENT-Z.md` | correspondance « Élément AGENT Z » → implémentation réelle |
| `agent-z/logs/` | journal des exécutions (preuves) |
| `Bilan_SOC_*.txt` | rapports de posture datés |

## Utilisation

```sh
cp orchestrateur/.env.example orchestrateur/.env.local   # puis renseigner les identifiants
cd orchestrateur
python orchestrator.py cyber "etat des agents"
python orchestrator.py research "syscollector"
```

Codes de sortie : `0` vérifié, `1` échec constaté, `2` domaine inconnu.

## Règles

- Aucun secret dans le code : identifiants via `WAZUH_*` ou `orchestrateur/.env.local` (non versionné).
- Aucun succès annoncé sans mesure : un agent qui n'a pas pu vérifier renvoie `False` et le dit.
- Les agents Wazuh apparaissent tous en `127.0.0.1` (relais WSL) : ne pas en déduire une localisation.
- Filtrer les recherches sur `agent.name`, jamais sur `agent.id` (l'ID change au réenrôlement).
