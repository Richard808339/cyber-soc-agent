#!/usr/bin/env python3
"""Collecteur SOC : la seule piece qui parle a Wazuh.

Wazuh tourne en local (WSL2/Docker) et n'est pas expose sur Internet. Ce script
tourne donc sur le PC qui heberge Wazuh, interroge l'API du manager et
l'indexeur, construit un snapshot et le pousse vers le tableau de bord.

Usage :
    python collector.py                 # un cycle, puis sortie
    python collector.py --loop 60       # cycle toutes les 60 s

Configuration (variables d'environnement ou fichier .env a cote du script) :
    WAZUH_API_URL       defaut https://localhost:55000
    WAZUH_API_USER      defaut wazuh-wui
    WAZUH_API_PASS      obligatoire pour les donnees Wazuh
    WAZUH_INDEXER_URL   defaut https://localhost:9200
    WAZUH_INDEXER_USER  defaut admin
    WAZUH_INDEXER_PASS  obligatoire pour les alertes
    SOC_DASHBOARD_URL   defaut http://127.0.0.1:8765
    SOC_INGEST_TOKEN    jeton shared avec le tableau de bord
    WAZUH_VERIFY_TLS    defaut 0 (certificats auto-signes du lab)
"""

import argparse
import hashlib
import json
import os
import platform
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import playbooks  # noqa: E402

try:
    # Garde-fou optionnel : le collecteur ne fait que de la lecture, mais s'il
    # venait a lancer une commande sensible elle serait arretee net.
    # Desactivable avec SOC_SHIELD=0.
    if os.environ.get("SOC_SHIELD", "1") != "0":
        import shield
        shield.install(agent="collector")
except Exception as _exc:  # jamais bloquant pour la collecte
    print("garde-fou indisponible :", _exc)

try:  # console Windows : evite UnicodeEncodeError sur les accents
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def load_dotenv(path=None):
    path = path or os.path.join(HERE, ".env")
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def env(name, default=None, required=False):
    val = os.environ.get(name, default)
    if required and not val:
        raise SystemExit("Variable manquante : %s (voir .env.example)" % name)
    return val


def _ctx():
    if env("WAZUH_VERIFY_TLS", "0") == "1":
        return ssl.create_default_context()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def http_json(url, method="GET", headers=None, body=None, timeout=20, auth=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if auth:
        import base64
        raw = ("%s:%s" % auth).encode("utf-8")
        req.add_header("Authorization", "Basic " + base64.b64encode(raw).decode("ascii"))
    with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as resp:
        return json.loads(resp.read().decode("utf-8"))


# --------------------------------------------------------------------------- #
# Wazuh API
# --------------------------------------------------------------------------- #
class WazuhAPI:
    def __init__(self):
        self.base = env("WAZUH_API_URL", "https://localhost:55000").rstrip("/")
        self.user = env("WAZUH_API_USER", "wazuh-wui")
        self.password = env("WAZUH_API_PASS", "")
        self._token = None

    def token(self):
        if self._token:
            return self._token
        if not self.password:
            raise RuntimeError("WAZUH_API_PASS non configure")
        raw = ("%s:%s" % (self.user, self.password)).encode("utf-8")
        import base64
        req = urllib.request.Request(self.base + "/security/user/authenticate?raw=true", method="POST")
        req.add_header("Authorization", "Basic " + base64.b64encode(raw).decode("ascii"))
        with urllib.request.urlopen(req, timeout=20, context=_ctx()) as resp:
            self._token = resp.read().decode("utf-8").strip().strip('"')
        return self._token

    def get(self, path, **params):
        url = self.base + path
        if params:
            qs = "&".join("%s=%s" % (k, v) for k, v in params.items())
            url += ("&" if "?" in url else "?") + qs
        req = urllib.request.Request(url)
        req.add_header("Authorization", "Bearer " + self.token())
        try:
            with urllib.request.urlopen(req, timeout=25, context=_ctx()) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                self._token = None
            raise

    def agents(self):
        payload = self.get(
            "/agents",
            select="id,name,ip,status,os.name,os.version,os.platform,lastKeepAlive,version,group",
            limit=500,
        )
        items = ((payload.get("data") or {}).get("affected_items")) or []
        out = []
        for a in items:
            out.append({
                "id": a.get("id"),
                "name": a.get("name"),
                "ip": a.get("ip"),
                "status": a.get("status"),
                "os": ((a.get("os") or {}).get("name")),
                "os_version": ((a.get("os") or {}).get("version")),
                "platform": ((a.get("os") or {}).get("platform")),
                "last_keepalive": a.get("lastKeepAlive"),
                "version": a.get("version"),
                "group": a.get("group"),
            })
        return out

    def manager_info(self):
        payload = self.get("/manager/info")
        items = ((payload.get("data") or {}).get("affected_items")) or [{}]
        return {k: items[0].get(k) for k in ("version", "type", "path", "uuid", "tz_name")}


# --------------------------------------------------------------------------- #
# Indexeur (alertes, vulnerabilites)
# --------------------------------------------------------------------------- #
class Indexer:
    def __init__(self):
        self.base = env("WAZUH_INDEXER_URL", "https://localhost:9200").rstrip("/")
        self.user = env("WAZUH_INDEXER_USER", "admin")
        self.password = env("WAZUH_INDEXER_PASS", "")

    def search(self, pattern, body, size=0, timeout=25):
        if not self.password:
            raise RuntimeError("WAZUH_INDEXER_PASS non configure")
        url = "%s/%s/_search?size=%d" % (self.base, pattern, size)
        return http_json(url, method="POST", body=body, timeout=timeout,
                         auth=(self.user, self.password))

    def alerts_window(self, hours=24):
        body = {
            "query": {"range": {"timestamp": {"gte": "now-%dh" % hours}}},
            "sort": [{"timestamp": "desc"}],
            "aggs": {
                "by_level": {"terms": {"field": "rule.level", "size": 25}},
                "by_rule": {"terms": {"field": "rule.description", "size": 12}},
                "by_agent": {"terms": {"field": "agent.name", "size": 15}},
                "by_src": {"terms": {"field": "data.srcip", "size": 8}},
                "by_mitre": {"terms": {"field": "rule.mitre.id", "size": 10}},
                "timeline": {"date_histogram": {"field": "timestamp", "fixed_interval": "1h",
                                                "min_doc_count": 0,
                                                "extended_bounds": {"min": "now-%dh" % hours,
                                                                    "max": "now"}}},
            },
        }
        res = self.search("wazuh-alerts-*", body, size=40)

        def buckets(name):
            return [{"key": b["key"] if not isinstance(b["key"], int) else str(b["key"]),
                     "count": b["doc_count"]}
                    for b in ((res.get("aggregations") or {}).get(name) or {}).get("buckets", [])]

        recent = []
        for hit in ((res.get("hits") or {}).get("hits") or []):
            s = hit.get("_source") or {}
            rule = s.get("rule") or {}
            mitre = (rule.get("mitre") or {}).get("id") or []
            item = {
                "ts": s.get("timestamp"),
                "agent": (s.get("agent") or {}).get("name"),
                "rule_id": rule.get("id"),
                "level": rule.get("level"),
                "description": rule.get("description"),
                "groups": rule.get("groups") or [],
                "mitre_ids": mitre,
                "srcip": (s.get("data") or {}).get("srcip"),
                "location": s.get("location"),
            }
            item["playbook"] = playbooks.match(item)
            item["fingerprint"] = hashlib.sha1(
                ("%s|%s|%s|%s" % (item["ts"], item["agent"], item["rule_id"], item["description"])).encode("utf-8")
            ).hexdigest()[:16]
            recent.append(item)

        return {
            "window_hours": hours,
            "total": ((res.get("hits") or {}).get("total") or {}).get("value", 0),
            "by_level": {b["key"]: b["count"] for b in buckets("by_level")},
            "top_rules": buckets("by_rule"),
            "by_agent": buckets("by_agent"),
            "top_sources": buckets("by_src"),
            "top_mitre": buckets("by_mitre"),
            "timeline": [{"ts": b.get("key_as_string"), "count": b["doc_count"]}
                         for b in ((res.get("aggregations") or {}).get("timeline") or {}).get("buckets", [])],
            "recent": recent[:40],
        }

    def health(self):
        """Etat du cluster d'indexation (green / yellow / red)."""
        return http_json(self.base + "/_cluster/health", timeout=15,
                         auth=(self.user, self.password))

    def vulnerabilities(self):
        body = {
            "query": {"match_all": {}},
            "aggs": {
                "by_severity": {"terms": {"field": "vulnerability.severity", "size": 6}},
                "by_agent": {"terms": {"field": "agent.name", "size": 10}},
            },
        }
        try:
            res = self.search("wazuh-states-vulnerabilities-*", body)
        except Exception as exc:
            return {"total": 0, "by_severity": {}, "by_agent": {}, "error": str(exc)[:120]}
        aggs = res.get("aggregations") or {}
        return {
            "total": ((res.get("hits") or {}).get("total") or {}).get("value", 0),
            "by_severity": {b["key"]: b["doc_count"] for b in (aggs.get("by_severity") or {}).get("buckets", [])},
            "by_agent": [{"key": b["key"], "count": b["doc_count"]}
                         for b in (aggs.get("by_agent") or {}).get("buckets", [])],
        }


# --------------------------------------------------------------------------- #
# Etat de la pile Wazuh (conteneurs Docker dans WSL2 + sante de l'indexeur)
# --------------------------------------------------------------------------- #
def _wsl(script, timeout=40):
    """Execute une commande dans la distro WSL qui heberge Wazuh (best effort)."""
    if env("SOC_STACK_PROBE", "1") != "1":
        return None
    distro = env("WAZUH_WSL_DISTRO", "wazuh") or "wazuh"
    try:
        proc = subprocess.run(
            ["wsl.exe", "-d", distro, "-e", "sh", "-c", script],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return (proc.stdout or "").replace("\r", "")
    except Exception:
        return None


def stack_status(indexer=None):
    """Conteneurs de la pile, refus d'enrolement recents, sante de l'indexeur."""
    out = {"available": False, "containers": [], "enrollment_rejected_30m": None,
           "indexer_health": None, "error": None}

    if indexer is not None:
        try:
            out["indexer_health"] = (indexer.health() or {}).get("status")
        except Exception as exc:
            out["error"] = "indexeur: %s" % str(exc)[:110]

    manager = env("WAZUH_MANAGER_CONTAINER", "single-node-wazuh.manager-1") or "single-node-wazuh.manager-1"
    script = (
        'docker ps --format "{{.Names}}|{{.Status}}" 2>/dev/null; '
        'echo "@@REJECTS@@"; '
        'docker logs --since 30m %s 2>&1 | grep -c "rejecting enrollment"'
        % manager
    )
    raw = _wsl(script)
    if raw is None:
        out["error"] = out["error"] or "WSL/Docker injoignable depuis ce poste"
        return out

    head, _, tail = raw.partition("@@REJECTS@@")
    for line in head.splitlines():
        if "|" not in line:
            continue
        name, _, status = line.partition("|")
        if name.strip():
            out["containers"].append({"name": name.strip(), "status": status.strip()})
    try:
        out["enrollment_rejected_30m"] = int((tail.strip() or "0").splitlines()[0])
    except Exception:
        out["enrollment_rejected_30m"] = None
    out["available"] = bool(out["containers"])
    if not out["available"]:
        out["error"] = out["error"] or "docker ps n'a rien renvoye"
    return out


# --------------------------------------------------------------------------- #
# Posture de l'hote local (pas besoin de droits Wazuh)
# --------------------------------------------------------------------------- #
def host_posture():
    info = {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    try:
        import psutil
        info["uptime_hours"] = round((time.time() - psutil.boot_time()) / 3600, 1)
    except Exception:
        info["uptime_hours"] = None
    return info


def build_snapshot():
    snap = {
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "collector": {"version": "1.0", "host": socket.gethostname()},
        "host": host_posture(),
        "agents": [],
        "alerts": {},
        "vulnerabilities": {},
        "stack": {},
        "manager": {},
        "errors": [],
    }

    api = WazuhAPI()
    idx = Indexer()

    try:
        snap["agents"] = api.agents()
    except Exception as exc:
        snap["errors"].append("agents: %s: %s" % (exc.__class__.__name__, str(exc)[:160]))

    try:
        snap["manager"] = api.manager_info()
    except Exception as exc:
        snap["errors"].append("manager: %s: %s" % (exc.__class__.__name__, str(exc)[:160]))

    try:
        alerts = idx.alerts_window(int(env("SOC_ALERT_WINDOW_HOURS", "24")))
        snap["alerts"] = {
            "total_24h": alerts["total"],
            "by_level": alerts["by_level"],
            "top_rules": alerts["top_rules"],
            "by_agent": alerts["by_agent"],
            "top_sources": alerts["top_sources"],
            "top_mitre": alerts["top_mitre"],
            "timeline": alerts["timeline"],
        }
        snap["recent_alerts"] = alerts["recent"]
    except Exception as exc:
        snap["errors"].append("alerts: %s: %s" % (exc.__class__.__name__, str(exc)[:160]))

    try:
        snap["vulnerabilities"] = idx.vulnerabilities()
    except Exception as exc:
        snap["errors"].append("vulnerabilities: %s" % str(exc)[:160])

    try:
        snap["stack"] = stack_status(idx)
    except Exception as exc:
        snap["stack"] = {"available": False, "error": str(exc)[:160]}

    return snap


def push(snapshot):
    url = env("SOC_DASHBOARD_URL", "http://127.0.0.1:8765").rstrip("/") + "/api/ingest"
    token = env("SOC_INGEST_TOKEN", "")
    body = json.dumps(snapshot, ensure_ascii=False, default=str).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.status, resp.read().decode("utf-8")


def main():
    ap = argparse.ArgumentParser(description="Collecteur Wazuh -> tableau de bord SOC")
    ap.add_argument("--loop", type=int, default=0, help="intervalle en secondes (0 = un seul cycle)")
    ap.add_argument("--dump", action="store_true", help="affiche le snapshot au lieu de le pousser")
    args = ap.parse_args()

    load_dotenv()
    while True:
        snap = build_snapshot()
        if args.dump:
            print(json.dumps(snap, ensure_ascii=False, indent=2, default=str)[:4000])
        else:
            try:
                status, text = push(snap)
                a = snap["alerts"]
                print("[%s] push HTTP %s | postes=%d alertes24h=%s erreurs=%d"
                      % (datetime.now().strftime("%H:%M:%S"), status, len(snap["agents"]),
                         a.get("total_24h"), len(snap["errors"])))
                for err in snap["errors"]:
                    print("   !", err)
            except Exception as exc:
                print("[%s] echec du push : %s: %s"
                      % (datetime.now().strftime("%H:%M:%S"), exc.__class__.__name__, str(exc)[:200]))
        if not args.loop:
            # Apres chaque collecte : y a-t-il eu un redemarrage non trace ?
            if not args.dump and os.environ.get("SOC_SHIELD", "1") != "0":
                try:
                    import broker
                    res = broker.detect()
                    for a in res.get("anomalies") or []:
                        print("   ? conteneur %s : %s" % (a["conteneur"], a["constat"]))
                except Exception as exc:
                    print("   ? controle de contournement indisponible : %s" % str(exc)[:120])
            break
        time.sleep(args.loop)


if __name__ == "__main__":
    main()
