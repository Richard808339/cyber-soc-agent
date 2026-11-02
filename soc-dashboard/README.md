# Tableau de bord SOC

Tableau de bord web pour le SOC : état des postes, alertes, bilan résumé, pistes de
réponse. Il s'appuie sur le Wazuh qui tourne dans WSL2 sur le poste (`/opt/wazuh-docker`,
manager v4.14.9) — sans jamais exposer ce Wazuh sur Internet.

Aucune dépendance : Python 3.9+ et sa bibliothèque standard. Pas de `pip install`.

## Le problème et la solution retenue

Wazuh tourne en local. Une application en ligne ne peut donc pas l'interroger : il
faudrait ouvrir le manager sur Internet, ce qui transforme un lab en cible.

Ce tableau de bord inverse le flux. C'est le **collecteur**, lancé sur le PC qui
héberge Wazuh, qui pousse un snapshot vers le tableau de bord :

```
   ┌──────────── PC local ────────────┐          ┌───── Tableau de bord ─────┐
   │ Wazuh manager (WSL2/Docker)      │          │ app.py (HTTP + SQLite)    │
   │   55000 API · 9200 indexer       │          │ /api/ingest (jeton)       │
   │            ▲                     │  HTTPS   │ /api/overview             │
   │      collector.py ───────────────┼─────────▶│ /api/summary              │
   └──────────────────────────────────┘  push    │ / (interface web)         │
                                                  └───────────────────────────┘
```

Conséquences :
- aucun port entrant ouvert sur le PC, aucun tunnel, aucun certificat à gérer ;
- le tableau de bord peut vivre sur une machine banale, un VPS ou un Raspberry Pi ;
- si le tableau de bord est compromis, l'attaquant n'obtient que les données déjà
  poussées, pas un accès au manager.

Les deux autres options (exposer Wazuh derrière un tunnel type Tailscale/Cloudflare
Access, ou publier l'API avec mTLS) restent possibles, mais elles donnent à une
application distante un chemin direct vers le manager. Le push est plus simple à
sécuriser et suffit ici.

## Contenu

| Fichier | Rôle |
|---|---|
| `app.py` | serveur HTTP : interface, API JSON, ingestion, SQLite |
| `collector.py` | interroge l'API Wazuh + l'indexeur, pousse le snapshot |
| `summarizer.py` | bilan : appel LLM (compatible OpenAI) ou moteur de règles hors ligne |
| `playbooks.py` | catalogue de pistes de réponse avec commandes prêtes |
| `socstore.py` | schéma et requêtes SQLite |
| `static/index.html` | interface (HTML/CSS/JS, aucun CDN) |
| `llm_stub.py` | faux fournisseur LLM compatible OpenAI, pour vérifier le bilan sans clé |
| `run-collector.bat` / `.vbs` | lancement silencieux du collecteur (tâche planifiée) |
| `test_soc.py` | 28 tests : métriques, score, diagnostic, bilan (dont le chemin LLM), playbooks, jetons, API |

## Démarrage

1. Configurer les identifiants (fichier local, jamais versionné) :

```bash
cp .env.example .env
# éditer .env : WAZUH_API_PASS, WAZUH_INDEXER_PASS, SOC_INGEST_TOKEN
python -c "import secrets;print(secrets.token_urlsafe(32))"   # pour le jeton
```

2. Lancer le tableau de bord :

```bash
python app.py                # http://127.0.0.1:8765
```

3. Alimenter en données (sur le PC qui héberge Wazuh) :

```bash
python collector.py --dump   # voir le snapshot sans le pousser
python collector.py          # un cycle
python collector.py --loop 60   # toutes les 60 s
```

4. Ouvrir http://127.0.0.1:8765

## Ce qu'affiche l'interface

- **KPI** : postes actifs, alertes 24 h, critiques (niveau ≥ 12), vulnérabilités,
  score de posture 0-100 (couverture des postes − bruit critique).
- **Alertes sur 24 h** : histogramme horaire issu de l'indexeur.
- **Règles les plus déclenchées** : top 8 avec barres proportionnelles.
- **Postes surveillés** : état, système, dernier contact, identifiant d'agent.
- **Bilan résumé** : texte en français, régénéré quand les données changent.
- **Vulnérabilités** : volumes par sévérité (`wazuh-states-vulnerabilities-*`).
- **Flux d'alertes** : filtrable par gravité, chaque ligne ouvre sa piste de réponse
  (étapes + commandes copiables). Lien direct : `/#pb=brute_force`.

## Le bilan : deux moteurs

`SOC_SUMMARY_ENGINE=auto` (défaut) :
- si `SOC_LLM_API_KEY` est défini → API compatible OpenAI
  (`SOC_LLM_BASE_URL`, `SOC_LLM_MODEL`, par défaut DeepSeek) ;
- sinon, ou si l'appel échoue (réseau, quota, clé invalide) → **moteur de règles**,
  hors ligne, déterministe : il rédige le bilan à partir des chiffres du snapshot.

Le repli est automatique et signalé dans la réponse (`fallback`). Aucune donnée
n'est inventée : le prompt ne contient que le snapshot, et le moteur de règles ne
cite que ce qu'il a reçu.

Régénération : le bilan est refait dès qu'il décrit des données plus anciennes que
le dernier snapshot, avec un intervalle minimal (`SOC_SUMMARY_MIN_INTERVAL`, 120 s)
pour éviter les appels LLM en rafale.

## Pistes de réponse

`playbooks.py` couvre : force brute, balayage de ports, intégrité de fichier,
vulnérabilité critique, malware, agent déconnecté, authentification suspecte,
élévation de privilèges, plus un repli générique. Le rattachement se fait par
identifiant de règle Wazuh connu, puis par mots-clés de la description et des
groupes d'alertes.

Rien n'est exécuté automatiquement : les commandes sont affichées pour l'analyste.
Les requêtes d'indexeur du catalogue ont été testées sur l'indexeur réel.

## API

| Méthode | Route | Usage |
|---|---|---|
| `POST` | `/api/ingest` | reçoit un snapshot (jeton Bearer `SOC_INGEST_TOKEN`) |
| `GET` | `/api/overview` | tout ce qu'affiche l'interface |
| `GET` | `/api/alerts?level=8&agent=…&playbook=…` | flux filtré |
| `GET` | `/api/summary` · `POST /api/summary/refresh` | bilan courant / régénération |
| `GET` | `/api/playbook/<cle>` | piste de réponse complète |
| `GET` | `/api/health` · `/api/history` | santé, historique des collectes |

## Sécurité

- `SOC_INGEST_TOKEN` : obligatoire en pratique ; sans lui, l'ingestion est ouverte.
- `SOC_READ_TOKEN` : si défini, toutes les routes `/api/*` exigent `X-SOC-Token`
  (ou `Authorization: Bearer`). L'interface demande alors le jeton au premier
  chargement et le garde dans le `localStorage` du navigateur.
  Pour amorcer sur un autre poste sans le taper : `http://hote:8765/#token=<jeton>`
  — le fragment n'est jamais envoyé au serveur, il est mémorisé puis retiré de l'URL.
  Vérifié : 401 sans jeton, 401 avec un mauvais jeton, 200 avec le bon.
- Écoute sur `127.0.0.1` par défaut. Pour un accès distant, préférer un reverse proxy
  TLS devant `SOC_BIND=0.0.0.0` plutôt qu'une exposition directe.
- `.env` et `soc.db` sont ignorés par git ; ne jamais versionner les identifiants.
- Le dépôt est public : les données SOC réelles doivent rester dans `soc.db`, pas
  dans des fichiers suivis par git.

## Notifications Telegram

Le tableau de bord pousse vers le bot Telegram (@CyberSOC_Agent68_bot) dès qu'un
constat **critique** ou **élevé** apparaît : conteneur arrêté, API Wazuh muette,
poste injoignable, indexeur rouge, refus d'enrôlement massif. Rien n'est envoyé
quand tout va bien, ce qui évite le bruit qui rend un canal d'alerte inutile.

```
.env :  SOC_TELEGRAM_TOKEN=<jeton du bot>
        SOC_TELEGRAM_CHAT_ID=<destinataire>
        SOC_NOTIFY=1                  (0 = coupe les notifications)
        SOC_NOTIFY_COOLDOWN=900       (anti-doublon : pas deux fois le même constat en 15 min)
        SOC_PUBLIC_URL=http://...     (lien ajouté au message, optionnel)
```

Commandes :

```bash
python notifier.py --test        # message de vérification (prouve que le bot est relié)
python notifier.py --digest      # bilan courant formaté pour Telegram
python notifier.py --dry-run     # affiche le message sans l'envoyer
```

Le message contient les chiffres clés (postes actifs, alertes 24 h, score), l'état
de la pile, puis les constats avec la première action à lancer en police monospace.
`notifier.py` n'utilise que `urllib` : aucune dépendance.

L'anti-doublon est stocké en base (`notifications`) : deux collectes successives avec
le même constat ne produisent qu'un seul message. Vérifié sur une instance isolée :
2 ingestions dégradées → 1 seul message (message_id 39).

## Diagnostic du SOC

Le collecteur lit aussi l'état de la pile (conteneurs Docker de la distro WSL,
`_cluster/health` de l'indexeur, refus d'enrôlement des 30 dernières minutes).
`summarizer.findings()` en tire des constats affichés en haut du tableau de bord,
chacun avec sa preuve et ses actions :

| Situation | Niveau |
|---|---|
| API Wazuh muette / aucun poste enregistré | critique |
| Conteneur arrêté | critique |
| Aucun signal sur 24 h | élevé |
| Poste injoignable | élevé |
| Indexeur en `red` (élevé) ou `yellow` (moyen) | élevé / moyen |
| Refus d'enrôlement > 5 en 30 min | moyen |
| Pile non inspectable depuis le poste | moyen |

Principe : un SOC silencieux n'est pas un SOC sain. Le diagnostic distingue « rien à
signaler » de « je ne vois plus rien », ce qui est le piège classique d'un tableau de
bord qui affiche fièrement « 0 alerte ».

## Tests

```bash
python test_soc.py       # 20 tests, aucun accès Wazuh ni clé LLM requis
```

Le chemin « bilan rédigé par un modèle » est vérifié sans clé : `llm_stub.py` est un
faux fournisseur compatible OpenAI qui renvoie un texte reprenant les chiffres reçus
dans le prompt. Le test prouve ainsi que le snapshot part bien en HTTP et que le texte
du modèle remplace celui du moteur de règles. Pour le voir dans l'interface :

```bash
python llm_stub.py --port 8899
# .env : SOC_LLM_API_KEY=stub  SOC_LLM_BASE_URL=http://127.0.0.1:8899/v1  SOC_LLM_MODEL=stub-model
# puis "Régénérer" dans l'interface : le badge passe à "LLM · stub-model"
```

## Planification de la collecte (Windows)

Le collecteur doit tourner régulièrement, sinon le tableau de bord vieillit. Une tâche
planifiée toutes les 5 minutes est déjà en place :

```
Tâche     : "SOC Dashboard Collector"
Action    : wscript.exe ...\run-collector.vbs   (lance run-collector.bat sans fenêtre)
Rythme    : toutes les 5 minutes, répétition illimitée
Compte    : utilisateur courant (Interactive uniquement : tourne quand la session est ouverte)
Journal   : soc-dashboard\collector.log
```

Recréer la tâche sur une autre machine :

```powershell
schtasks /Create /TN "SOC Dashboard Collector" `
  /TR "wscript.exe \"C:\chemin\vers\soc-dashboard\run-collector.vbs\"" `
  /SC MINUTE /MO 5 /F
schtasks /Run /TN "SOC Dashboard Collector"     # test immédiat
schtasks /End /TN "SOC Dashboard Collector"     # arrêt
schtasks /Delete /TN "SOC Dashboard Collector" /F
```

Dans `run-collector.bat`, `PY` pointe vers l'interpréteur utilisé. Adapte ce chemin si
Python est installé ailleurs. Pour que la collecte tourne même session fermée, il faut
recréer la tâche avec un compte et un mot de passe (`/RU ... /RP ...`), ce qui demande
les droits administrateur.

## Limites connues

- Le flux d'alertes ne conserve que les 40 dernières par cycle ; l'historique
  complet reste dans Wazuh. Les statistiques (top règles, sévérités) viennent des
  agrégations, pas des 40 lignes.
- Le score de posture est un indicateur maison simple (couverture + bruit critique),
  pas une norme.
- Un seul manager pour l'instant : multi-manager demanderait une clé de site dans le
  schéma.
