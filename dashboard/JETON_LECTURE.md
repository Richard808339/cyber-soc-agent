# Jeton de lecture — SOC KOFFI

Deux niveaux, deux usages. Les deux ont été testés (lecture acceptée, écriture refusée).

## 1. Indexer (9200) — le compte de lecture propre

| Champ | Valeur |
|---|---|
| Utilisateur | `soc-reader` |
| Mot de passe | `Lecture-SOC-2026` |
| Rôle | `soc_readonly` : `cluster_composite_ops_ro`, `cluster_monitor`, `read` sur `*` |

Testé : `GET /_cluster/health` → **200**, `GET /wazuh-alerts-*/_search` → **200**,
`PUT /_plugins/_security/api/roles/test` → **403**, `POST /test-soc/_doc` → **403**.

```sh
curl -k -u soc-reader:Lecture-SOC-2026 "https://localhost:9200/_cluster/health"
curl -k -u soc-reader:Lecture-SOC-2026 -H 'Content-Type: application/json' \
  "https://localhost:9200/wazuh-alerts-*/_search" -d '{"size":3,"sort":[{"@timestamp":"desc"}]}'
```

En-tête `Authorization` équivalent : `Basic <base64(soc-reader:Lecture-SOC-2026)>`.

## 2. API Wazuh (55000) — jeton JWT

Un JWT expire en 900 s : ce n'est pas un secret durable, c'est un jeton de session.
On le redemande à la demande :

```sh
sh dashboard/read_token.sh                 # → JWT sur stdout
sh dashboard/read_token.sh soc-reader MDP  # autre compte
```

Le compte `soc-reader` existe aussi côté API (`id=100`), mais **les rôles d'API ne
peuvent pas être attribués via l'API en 4.14.9**. Mesuré :

| Tentative | Code |
|---|---|
| `POST /security/users` avec `roles_list` | 400 `Invalid field found {'roles_list'}` |
| `POST /security/users/100` avec `roles` | 405 |
| `PUT /security/users/100` avec `roles` ou `roles_list` | 400 |
| `PATCH /security/users/100` | 405 |
| `POST /security/users/100/roles` | 400 |

Le compte reste donc sans rôle, ce qui donne un profil bâtard, mesuré au 2026-11-05 :

| Requête | Résultat |
|---|---|
| `GET /agents` | 200 |
| `GET /security/users` | 200 ← **anormal, à corriger** |
| `GET /manager/info` | 403 |
| `GET /syscheck/000` | 403 |
| `POST /agents`, `DELETE /agents` | 403 |

Conclusion : pour lire les alertes et les agents, le compte d'indexer (niveau 1) est le
bon outil. Pour l'API, garder `wazuh-wui` en local, ou corriger les rôles à la main dans
l'indexer de sécurité puis revérifier.

## Recommandations

- Ne pas exposer 9200 ni 55000 : ces comptes de lecture valent pour la machine.
- Le mot de passe `Lecture-SOC-2026` est passé par un chat : à changer avant tout usage réel
  (`PUT /_plugins/_security/api/internalusers/soc-reader` avec un nouveau `password`).
- L'accès `GET /security/users` accordé à un compte sans rôle doit être fermé : c'est une
  énumération de comptes offerte.
