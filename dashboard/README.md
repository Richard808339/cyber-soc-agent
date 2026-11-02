# Tableau de bord SOC — KOFFI

Interface web locale qui agrège l'état des postes, les alertes, un bilan et des pistes
de réponse. Conçue autour d'une contrainte : **Wazuh tourne en local, donc rien
d'externe ne peut l'interroger directement**.

## Architecture : l'agent pousse, le tableau de bord lit

```
Wazuh (WSL) ──► collector.py ──► data/snapshot.json ──► server.py ──► navigateur
   API 55000                    (contrat de données)      HTTP local
   indexer 9200
```

- Le serveur **ne contacte jamais** Wazuh : il sert un fichier JSON produit par l'agent.
- Conséquence : il n'y a rien à exposer sur Internet pour que le tableau de bord fonctionne.
  On peut publier `snapshot.json` (ou `preview.html`) où l'on veut, même par mail.
- `POST /api/refresh` relance la collecte à la demande.

## Fichiers

| Fichier | Rôle |
|---|---|
| `collector.py` | interroge l'API Wazuh via WSL, calcule score, findings, pistes ; écrit `data/snapshot.json` |
| `server.py` | serveur HTTP (stdlib) : `/`, `/api/snapshot`, `/api/refresh`, `/health` |
| `web/index.html` | interface (aucune dépendance, aucun CDN) |
| `state/ai_summary.json` | bilan rédigé par l'agent ; à défaut, une synthèse par règles est calculée |
| `make_preview.py` | produit `preview.html` autonome (snapshot injecté) |
| `data/snapshot.json` | dernière collecte |

## Lancer

```sh
python collector.py            # une collecte
python server.py               # http://127.0.0.1:8099/
python make_preview.py         # preview.html hors ligne
```

Variables : `WAZUH_UI_PASS` / `WAZUH_IDX_PASS` (ou `../orchestrateur/.env.local`),
`DASH_HOST` (défaut 127.0.0.1), `DASH_PORT` (défaut 8099).

## Ce que l'interface affiche

- **Score de posture** calculé : agents hors ligne, inventaire manquant, indexer non vert,
  part de bruit, absence d'alerte critique.
- **Postes** : identifiant, nom, état, dernier keepalive, OS, présence de l'inventaire syscollector.
- **Alertes 24 h** : volume, répartition par niveau, chronologie horaire, règles les plus
  fréquentes, dernières alertes de niveau >= 10.
- **Bilan** : synthèse de l'agent si `state/ai_summary.json` existe, sinon synthèse par règles.
- **Pistes de réponse** : une fiche par problème, avec la preuve et la procédure (commandes).

## Exposer à distance, si un jour c'est nécessaire

1. **Le plus sûr : ne rien exposer.** `preview.html` (ou `snapshot.json`) est autonome :
   on l'envoie, on le consulte, aucune surface réseau.
2. **Tunnel SSH** vers le serveur local : `ssh -L 8099:127.0.0.1:8099 user@pc`, puis
   `http://localhost:8099` chez soi. Aucun port ouvert publiquement.
3. **Tunnel sortant** (Cloudflare Tunnel, Tailscale) : la machine initie la connexion,
   pas de redirection de port entrante, et mettre une authentification devant.
4. **N'exposer ni 9200 (indexer) ni 55000 (API)** : ces ports donnent un accès total aux
   données et aux comptes. Le dashboard n'en a pas besoin, le collector oui, en local.

## Limites connues

- La collecte dépend de l'API Wazuh : si `wazuh-apid` est arrêté (déjà vu après un
  redémarrage sous pression mémoire), le snapshot se vide. L'interface le signale alors
  par une piste « API Wazuh muette » et un score dégradé, plutôt que d'afficher du vide.
- Pas d'authentification sur le serveur local : il écoute sur 127.0.0.1 uniquement.
  Si `DASH_HOST` est changé pour 0.0.0.0, mettre un reverse-proxy authentifié devant.
