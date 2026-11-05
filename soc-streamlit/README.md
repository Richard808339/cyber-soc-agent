# Cyber SOC — tableau de bord Streamlit

Interface Streamlit en lecture seule sur les données réelles du SOC local :

| Source | Contenu |
|---|---|
| `soc-dashboard/soc.db` → `alerts` | journal des événements de sécurité (879 alertes) |
| `soc-dashboard/soc.db` → `approvals`, `approval_audit` | actions sensibles soumises à approbation humaine |
| orchestrateur `127.0.0.1:8000` | 12 agents du lab, statuts et dernières tâches |

## Pourquoi un dossier séparé

`soc-dashboard` est **sans aucune dépendance** (bibliothèque standard seule) : c'est une
décision de conception documentée, pas un oubli. Streamlit et pandas apportent des dizaines
de paquets ; ils vivent donc ici, dans leur propre environnement virtuel, et ne contaminent
pas le tableau de bord principal.

## Démarrage

```powershell
cd C:\Users\HP\Documents\security\soc-streamlit
.\.venv\Scripts\python.exe -m streamlit run app.py --server.port 8501
```

Puis http://127.0.0.1:8501

## Variables reconnues

| Variable | Défaut | Rôle |
|---|---|---|
| `SOC_DB` | `../soc-dashboard/soc.db` | base SQLite lue |
| `ORCHESTRATOR_URL` | `http://127.0.0.1:8000` | orchestrateur d'agents |
| `ORCH_KEY` | lu dans `soc-dashboard/.env` | en-tête `X-Orchestrator-Key` |

Les valeurs ne sont jamais affichées à l'écran.

## Ce que la page ne fait pas

Elle ne modifie rien : ni alertes, ni approbations. Les décisions passent par le broker
(CLI ou tableau de bord principal). C'est volontaire — une page de supervision qui peut
exécuter une action sensible est une page à protéger autrement.

## Note sur le schéma

Il n'existe **pas** de base `cyber_soc.db` ni de tables `security_events` /
`audit_actions` sur cette machine : ce sont des noms d'exemple. Les tables réelles sont
celles listées plus haut, avec `alerts.level` (0-15) et non `severity`, et
`approvals.status` (`pending`, `approved`, `denied`, `executed`) et non
`execution_status`.
