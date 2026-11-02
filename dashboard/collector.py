"""Collecteur du tableau de bord SOC.

Modele : le tableau de bord ne parle JAMAIS a Wazuh. Un agent collecte, ecrit un
snapshot JSON, le tableau de bord lit le snapshot. C'est ce qui permet de le servir
depuis n'importe ou plus tard (le PC n'a qu'a pousser le fichier).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
STATE = ROOT / "state"
DATA.mkdir(exist_ok=True)
STATE.mkdir(exist_ok=True)

DISTRO = os.environ.get("WAZUH_DISTRO", "wazuh")
API = "https://localhost:55000"
IDX = "https://localhost:9200"
UI_USER = os.environ.get("WAZUH_UI_USER", "wazuh-wui")
UI_PASS = os.environ.get("WAZUH_UI_PASS", "")
IDX_PASS = os.environ.get("WAZUH_IDX_PASS", "")
ENV_LOCAL = Path(__file__).resolve().parent.parent / "orchestrateur" / ".env.local"


def _load_env() -> None:
    global UI_PASS, IDX_PASS
    if UI_PASS and IDX_PASS:
        return
    if ENV_LOCAL.exists():
        for line in ENV_LOCAL.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())
        UI_PASS = os.environ.get("WAZUH_UI_PASS", "")
        IDX_PASS = os.environ.get("WAZUH_IDX_PASS", "")


REMOTE = """
TOK=$(curl -sk -u "{ui}:{pui}" -X POST {api}/security/user/authenticate | grep -o '"token": *"[^"]*"' | cut -d'"' -f4)
echo "===AGENTS==="
curl -sk -H "Authorization: Bearer $TOK" "{api}/agents?limit=50&select=id,name,status,lastKeepAlive,version,ip,os.name"
echo
echo "===ALERTS==="
curl -sk -u "admin:{pidx}" -H 'Content-Type: application/json' "{idx}/wazuh-alerts-*/_search" -d '{{"size":0,"query":{{"range":{{"@timestamp":{{"gte":"now-24h"}}}}}},
 "aggs":{{"lvl":{{"terms":{{"field":"rule.level","size":16,"order":{{"_key":"desc"}}}}}},
         "top":{{"terms":{{"field":"rule.description","size":10}}}},
         "agt":{{"terms":{{"field":"agent.name","size":10}}}},
         "hour":{{"date_histogram":{{"field":"@timestamp","fixed_interval":"1h","min_doc_count":0,"extended_bounds":{{"min":"now-24h","max":"now"}}}}}}}}}}'
echo
echo "===CRIT==="
curl -sk -u "admin:{pidx}" -H 'Content-Type: application/json' "{idx}/wazuh-alerts-*/_search" -d '{{"size":5,"sort":[{{"@timestamp":"desc"}}],
 "query":{{"bool":{{"must":[{{"range":{{"@timestamp":{{"gte":"now-7d"}}}}}},{{"range":{{"rule.level":{{"gte":10}}}}}}]}}}},
 "_source":["@timestamp","agent.name","rule.level","rule.description"]}}'
echo
echo "===INV==="
curl -sk -u "admin:{pidx}" "{idx}/_cat/indices/wazuh-states-inventory-system*?h=index"
echo
echo "===HEALTH==="
curl -sk -u "admin:{pidx}" "{idx}/_cluster/health"
echo
echo "===DOCKER==="
docker ps --format "{{{{.Names}}}}|{{{{.Status}}}}|{{{{.Image}}}}" 2>/dev/null
echo
echo "===ENROLL==="
docker logs --since 30m single-node-wazuh.manager-1 2>&1 | grep -c "rejecting enrollment" || true
"""


def _wsl(script: str) -> str:
    proc = subprocess.run(
        ["wsl.exe", "-d", DISTRO, "-e", "sh", "-c", script],
        capture_output=True, text=True, timeout=180, encoding="utf-8", errors="replace",
    )
    return (proc.stdout or "").replace("\r", "")


def _sec(raw: str, name: str) -> str:
    mark = f"==={name}==="
    if mark not in raw:
        return ""
    rest = raw.split(mark, 1)[1]
    for nxt in ("AGENTS", "ALERTS", "CRIT", "INV", "HEALTH", "DOCKER", "ENROLL"):
        m = f"==={nxt}==="
        if nxt != name and m in rest:
            rest = rest.split(m, 1)[0]
    return rest.strip()


def _j(txt: str, default=None):
    try:
        return json.loads(txt)
    except Exception:
        return default if default is not None else {}


def _gh_repo() -> dict:
    try:
        out = subprocess.run(
            ["C:/Program Files/GitHub CLI/gh.exe", "issue", "list", "--state", "open",
             "--limit", "10", "--json", "number,title,url"],
            capture_output=True, text=True, timeout=45, cwd=str(ROOT.parent),
        )
        if out.returncode != 0:
            return {"repo": None, "open_issues": []}
        return {"repo": "Richard808339/cyber-soc-agent", "open_issues": json.loads(out.stdout)}
    except Exception:
        return {"repo": None, "open_issues": []}


def _ai_summary(agents, alerts, findings) -> dict:
    """Synthese : celle du fichier d'etat si l'agent en a produit une, sinon reglee."""
    f = STATE / "ai_summary.json"
    if f.exists():
        s = _j(f.read_text(encoding="utf-8"), {})
        if s.get("bullets"):
            s["source"] = "agent"
            return s
    total = alerts.get("total_24h", 0)
    crit = alerts.get("critical_7d", 0)
    down = [a["name"] for a in agents if a["status"] != "active"]
    no = [a["name"] for a in agents if not a["inventory"]]
    bullets = [
        f"{len(agents)} agent(s) enregistre(s), {len(down)} hors ligne."
        + (f" Hors ligne : {', '.join(down)}." if down else ""),
        f"{total} alertes sur 24 h, dont {crit} de niveau >= 10 sur 7 jours.",
        ("Couverture d'inventaire incomplete : " + ", ".join(no) + ".")
        if no else "Inventaire syscollector complet sur les actifs.",
        f"{len(findings)} piste(s) de reponse ouverte(s), traitees par ordre de gravite.",
    ]
    return {"headline": f"SOC {'degrade' if findings else 'stable'}", "bullets": bullets, "source": "regles"}


def build_snapshot() -> dict:
    _load_env()
    raw = _wsl(REMOTE.format(ui=UI_USER, pui=UI_PASS, api=API, idx=IDX, pidx=IDX_PASS))

    agents_raw = _j(_sec(raw, "AGENTS"), {})
    inv_lines = [l.strip() for l in _sec(raw, "INV").splitlines() if l.strip()]
    health = _j(_sec(raw, "HEALTH"), {})
    docker = [l.split("|") for l in _sec(raw, "DOCKER").splitlines() if "|" in l]
    rejects = _sec(raw, "ENROLL")

    agents = []
    for a in agents_raw.get("data", {}).get("affected_items", []):
        name = a.get("name", "?")
        osname = (a.get("os") or {}).get("name") or ""
        agents.append({
            "id": a.get("id"),
            "name": name,
            "status": a.get("status"),
            "ip": a.get("ip"),
            "version": (a.get("version") or "").replace("Wazuh ", ""),
            "last_keepalive": (a.get("lastKeepAlive") or "")[:19],
            "os": osname,
            "inventory": any(i.endswith(f"-{name}") for i in inv_lines),
        })

    al = _j(_sec(raw, "ALERTS"), {})
    buckets = (al.get("aggregations", {}).get("lvl", {}) or {}).get("buckets", [])
    total_alerts = (al.get("hits", {}).get("total", {}) or {}).get("value", 0)
    by_level = {str(b["key"]): b["doc_count"] for b in buckets}
    top_rules = [{"rule": b["key"], "count": b["doc_count"]}
                 for b in (al.get("aggregations", {}).get("top", {}) or {}).get("buckets", [])]
    by_agent = [{"name": b["key"], "count": b["doc_count"]}
                for b in (al.get("aggregations", {}).get("agt", {}) or {}).get("buckets", [])]
    hourly = [{"t": b["key_as_string"][11:16], "count": b["doc_count"]}
              for b in (al.get("aggregations", {}).get("hour", {}) or {}).get("buckets", [])]

    cr = _j(_sec(raw, "CRIT"), {})
    critical = [{
        "time": h["_source"].get("@timestamp", "")[:19],
        "agent": (h["_source"].get("agent") or {}).get("name"),
        "level": (h["_source"].get("rule") or {}).get("level"),
        "rule": (h["_source"].get("rule") or {}).get("description"),
    } for h in cr.get("hits", {}).get("hits", [])]
    critical_total = (cr.get("hits", {}).get("total", {}) or {}).get("value", 0)

    alerts = {"total_24h": total_alerts, "by_level": by_level, "top_rules": top_rules,
              "by_agent": by_agent, "hourly": hourly,
              "critical_7d": critical_total, "critical_samples": critical}

    # cout des services non essentiels exposes : on reste factuel, rien d'invente
    findings = []
    if not agents:
        findings.append({
            "id": "api-down", "severity": "critique",
            "title": "API Wazuh muette : aucun agent lisible",
            "detail": "La collecte n'a ramene aucune liste d'agents. Soit l'api wazuh-apid est arretee, soit le manager ne repond pas.",
            "evidence": "GET https://localhost:55000/agents sans reponse exploitable",
            "playbook": [
                "docker logs --tail 30 single-node-wazuh.manager-1 | grep -i apid",
                "Si 'wazuh-apid did not start correctly' : docker restart single-node-wazuh.manager-1",
                "Verifier ensuite : curl -sk -o /dev/null -w '%{http_code}' -u ... https://localhost:55000/security/user/authenticate",
            ],
        })
    if total_alerts == 0:
        findings.append({
            "id": "silent", "severity": "majeur",
            "title": "Aucun signal sur 24 h",
            "detail": "Zero alerte indexee : SOC a l'arret, agents muets, ou poste eteint. Un SOC silencieux n'est pas un SOC sain.",
            "evidence": "agregation @timestamp >= now-24h sur wazuh-alerts-*",
            "playbook": [
                "Verifier les conteneurs : docker ps",
                "Verifier la connexion d'un agent : GET /agents (status active + keepalive recent)",
                "Si le poste etait eteint, le dire dans le bilan plutot que de conclure a l'absence d'incident",
            ],
        })
    for a in agents:
        if a["id"] == "000":
            continue
        if a["status"] != "active":
            findings.append({
                "id": f"agent-down-{a['id']}", "severity": "critique",
                "title": f"Agent {a['name']} hors ligne",
                "detail": f"Dernier keepalive {a['last_keepalive']}.",
                "evidence": "GET /agents, champ status",
                "playbook": [
                    "docker logs --since 10m single-node-wazuh.manager-1 | grep authd",
                    "Si boucle 'rejecting enrollment' : supprimer l'enregistrement puis laisser le re-enrolement",
                    "Sur le poste : Restart-Service WazuhSvc",
                ],
            })
        if not a["inventory"]:
            findings.append({
                "id": f"no-inventory-{a['id']}", "severity": "majeur",
                "title": f"Inventaire absent pour {a['name']}",
                "detail": "Aucun index wazuh-states-inventory-*-<agent> : ni paquets, ni ports, ni vulnerabilites.",
                "evidence": f"_cat/indices/wazuh-states-inventory-system* ({len(inv_lines)} index, manager seulement)",
                "playbook": [
                    "Verifier <wodle name=\"syscollector\"> dans %PROGRAMFILES(X86)%\\ossec-agent\\ossec.conf",
                    "Activer : <disabled>no</disabled>, intervals 3600",
                    "Restart-Service WazuhSvc, puis attendre un cycle (1 h)",
                ],
            })
    noise = (by_level.get("3", 0) + by_level.get("7", 0)) / total_alerts if total_alerts else 0
    if noise > 0.75:
        findings.append({
            "id": "noise", "severity": "majeur",
            "title": f"Bruit d'alertes : {int(noise * 100)} % en niveaux 3 et 7",
            "detail": "Le signal utile est noye : aucune regle de correlation n'est exploitable en l'etat.",
            "evidence": f"agregation rule.level sur 24 h ({total_alerts} alertes)",
            "playbook": [
                "Consulter a partir du niveau 7",
                "Desactiver Windows Logon Success / Software protection en niveaux 3",
                "Mesurer a nouveau le ratio apres 24 h",
            ],
        })
    if critical_total == 0 and total_alerts > 0:
        findings.append({
            "id": "no-critical", "severity": "info",
            "title": "Aucune alerte critique (>= 10) sur 7 jours",
            "detail": "A verifier : capacite de detection non prouvee, ou absence reelle d'incident.",
            "evidence": "recherche rule.level >= 10 sur 7 jours",
            "playbook": ["Injecter un evenement test (echecs 4625 repetes) et verifier qu'il remonte >= 10"],
        })
    if rejects and rejects.strip() not in ("", "0"):
        findings.append({
            "id": "enroll", "severity": "majeur",
            "title": f"{rejects.strip()} refus d'enrolement sur 30 min",
            "detail": "Un agent redemande une cle en boucle : il perd sa connexion au manager.",
            "evidence": "docker logs manager | grep 'rejecting enrollment'",
            "playbook": ["Verifier client.keys cote agent", "Supprimer l'enregistrement fantome puis re-enroler"],
        })

    score = 100
    score -= 25 * sum(1 for a in agents if a["id"] != "000" and a["status"] != "active")
    score -= 10 * sum(1 for a in agents if a["id"] != "000" and not a["inventory"])
    score -= 0 if health.get("status") == "green" else 15
    score -= 10 if noise > 0.75 else 0
    score -= 10 if critical_total == 0 else 0
    score = max(0, min(100, score))

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "soc": {
            "version": "Wazuh 4.14.9",
            "mode": "single-node",
            "indexer": health.get("status", "inconnu"),
            "containers": [{"name": c[0], "status": c[1], "image": c[2]} for c in docker],
        },
        "score": score,
        "agents": agents,
        "alerts": alerts,
        "findings": findings,
        "ai_summary": _ai_summary(agents, alerts, findings),
        "github": _gh_repo(),
        "source": "wazuh-api + indexer (lecture seule)",
    }


def main() -> int:
    snap = build_snapshot()
    (DATA / "snapshot.json").write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"snapshot ecrit : {DATA / 'snapshot.json'}")
    print(f"  agents={len(snap['agents'])} alertes24h={snap['alerts']['total_24h']} "
          f"score={snap['score']} findings={len(snap['findings'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
