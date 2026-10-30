# Élément AGENT Z → implémentation réelle dans Hermes

Instanciation de la fiche « HACKTUALIZ | ACADEMY — Élément AGENT Z » pour l'agent
**Cyber SOC KOFFI**. Dernière colonne : ce qui existe réellement sur cette machine,
vérifié le 29/10/2026 à 06:20Z. Aucune case n'est cochée sans chemin ou commande.

| Élément | Dans Hermes, concrètement | Ici, valeur réelle | État |
|---|---|---|---|
| Purpose / identité | SOUL.md / instructions | `AppData\Local\hermes\SOUL.md` (607 o) — prompt générique Nous, **pas** une identité SOC | à spécialiser |
| Mission | instructions / contexte projet | `Documents\security\agent-z\AGENT.md` §Mission | créé |
| Goal | instructions + mission | `AGENT.md` §Goal — 4 priorités ordonnées (actif muet, exposition critique, preuve, réversibilité) | créé |
| Context | .hermes.md, AGENTS.md, CLAUDE.md, .cursorrules | `agent-z\AGENTS.md` (topologie, chemins, règles de lecture, pièges) | créé |
| Knowledge | fichiers de connaissance, skills, source externe | `agent-z\knowledge\soc-facts.md` (mesures datées) + 2 bilans `Bilan_SOC_*.txt` | créé |
| RAG | à construire, pas « le RAG d'Hermes » | `agents/research_agent.py` : recherche lexicale sur `Documents\security` (3 fichiers texte, 21 occurrences trouvées). Pas d'embeddings, pas d'index vectoriel — assumé et nommé | partiel |
| Tools | toolsets Hermes | `cli: file, skills, terminal, vision` ; désactivés : web, search, cronjob, delegation, memory, kanban… | volontairement réduit |
| Tool spécifique | toolset / MCP / skill | skill `devops/host-security-posture-audit` (+ `references/siem-bilan-wazuh.md`, `references/port-risk-map.md`, `scripts/`) ; skill `devops/wsl2-docker-stacks` ; aucun MCP | existant |
| Permissions | config outils + OS + approbations | Session **non élevée** : pare-feu, SMB, services, ossec.conf de l'agent ⇒ approbation. Deux demandes expirées sans réponse le 28/10 | contrainte réelle |
| Memory | memories/, MEMORY.md, USER.md | `memories\` **vide**, `config.yaml` : `memory_enabled: false`, toolset `memory` désactivé | absent |
| Skills | skills/ | 12 catégories, 1 skill SOC pertinent, 0 skill spécifique « SOC KOFFI » | existant |
| API keys | .env | 13 variables (DEEPSEEK_API_KEY, GOOGLE_API_KEY…) ; **aucune** clé Wazuh : identifiants du labo en dur dans `cyber_agent.py`, surchargables par `WAZUH_UI_PASS` / `WAZUH_IDX_PASS` | à durcir |
| Configuration | config.yaml | `config.yaml` : modèle `deepseek-v4-flash-vision-exp`, 194 lignes de réglages | existant |
| Logs | logs/ | `AppData\Local\hermes\logs\` (errors.log 600 Ko) + `agent-z\logs\run-*.log` (2 exécutions horodatées) | existant |
| Données de mission | fichiers projet / DB / API | API Wazuh 55000, indexer 9200, rapports du projet | existant |
| Stop condition | instruction + logique | `AGENT.md` §Stop condition : élévation non approuvée, chiffre non mesurable, hors périmètre, 3 échecs | créé |
| Validation | instruction + outil/test + critères | Codes de sortie de l'orchestrateur : 0 vérifié / 1 échec / 2 domaine inconnu, mesurés (0, 1, 2) | opérationnel |
| Evidence | fichiers/logs/tests/traces | `agent-z\logs\run-20261029T061810Z.log` (échec SOC éteint), `run-20261029T062026Z.log` (SOC relancé, 1547 alertes) | existant |
| Integration | MCP / API / CLI / service | WSL + docker compose + API REST Wazuh ; `orchestrator.py` (routes cyber / builder / research) | opérationnel |

## Ce que la fiche ne dit pas et qui compte ici

1. **Memory est le seul élément totalement absent.** Tout ce qui a été appris sur ce SOC vit
   dans des fichiers du projet, pas dans la mémoire de l'agent. Activer `memory_enabled: true`
   et le toolset `memory` est un changement de configuration globale — non fait sans accord.
2. **Le Purpose n'est pas celui d'un agent SOC.** SOUL.md est le prompt générique de Hermes.
   La spécialisation vit dans AGENT.md, qui n'est lu que si on le demande explicitement.
3. **Permissions ≠ champ dans un fichier.** Ici la contrainte est un UAC et une approbation
   d'outil qui expire : c'est elle qui a empêché la remédiation pare-feu, pas une option.
4. **Le SOC ne redémarre pas tout seul** (pas de systemd, dockerd lancé à la main). Un agent
   qui « vérifie le SOC » doit d'abord vérifier qu'il tourne — constaté le 29/10 à 06:18Z.
