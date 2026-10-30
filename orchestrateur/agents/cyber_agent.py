"""Cyber Agent : interroge reellement le SOC Wazuh qui tourne dans WSL.

Aucune valeur n'est inventee : si l'API ne repond pas, l'agent le dit et renvoie
(False, message). Le nom d'agent et l'ID sont lus dans les donnees du manager.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

DISTRO = os.environ.get("WAZUH_DISTRO", "wazuh")
API = "https://localhost:55000"
IDX = "https://localhost:9200"
UI_USER = os.environ.get("WAZUH_UI_USER", "wazuh-wui")
ENV_LOCAL = Path(__file__).resolve().parent.parent / ".env.local"

MARK_AGENTS = "===AGENTS==="
MARK_ALERTS = "===ALERTS==="
MARK_INV = "===INV==="


def _load_local_env() -> None:
    """Charge orchestrateur/.env.local (non versionne) dans os.environ."""
    if not ENV_LOCAL.exists():
        return
    for line in ENV_LOCAL.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _creds() -> tuple[str, str]:
    """Identifiants du SOC. Aucun secret n'est ecrit dans le code versionne."""
    ui_pass = os.environ.get("WAZUH_UI_PASS")
    idx_pass = os.environ.get("WAZUH_IDX_PASS")
    if not (ui_pass and idx_pass):
        _load_local_env()
        ui_pass = os.environ.get("WAZUH_UI_PASS")
        idx_pass = os.environ.get("WAZUH_IDX_PASS")
    if not (ui_pass and idx_pass):
        raise RuntimeError(
            "identifiants absents : definir WAZUH_UI_PASS et WAZUH_IDX_PASS "
            f"dans l'environnement ou dans {ENV_LOCAL} (voir .env.example)"
        )
    return ui_pass, idx_pass


def _build_script(ui_pass: str, idx_pass: str) -> str:
    return f"""
TOK=$(curl -sk -u "{UI_USER}:{ui_pass}" -X POST {API}/security/user/authenticate | grep -o '"token": *"[^"]*"' | cut -d'"' -f4)
if [ -z "$TOK" ]; then echo "AUTH_FAILED"; exit 3; fi
echo {MARK_AGENTS}
curl -sk -H "Authorization: Bearer $TOK" "{API}/agents?limit=50&select=id,name,status,lastKeepAlive,version,ip,os.name"
echo
echo {MARK_ALERTS}
curl -sk -u "admin:{idx_pass}" -H 'Content-Type: application/json' "{IDX}/wazuh-alerts-*/_search" \\
  -d '{{"size":0,"query":{{"range":{{"@timestamp":{{"gte":"now-24h"}}}}}},
       "aggs":{{"lvl":{{"terms":{{"field":"rule.level","size":12}}}},
               "ag":{{"terms":{{"field":"agent.id","size":12}}}}}}}}'
echo
echo {MARK_INV}
curl -sk -u "admin:{idx_pass}" "{IDX}/_cat/indices/wazuh-states-inventory-system*?h=index"
"""


def _wsl_run(script: str) -> str:
    """Execute un script sh dans la distribution Wazuh et renvoie sa sortie."""
    try:
        proc = subprocess.run(
            ["wsl.exe", "-d", DISTRO, "-e", "sh", "-c", script],
            capture_output=True, text=True, timeout=120, encoding="utf-8", errors="replace",
        )
    except FileNotFoundError:
        raise RuntimeError("wsl.exe introuvable : WSL n'est pas accessible depuis ce shell")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"pas de reponse du SOC apres 120 s (distribution {DISTRO})")
    out = (proc.stdout or "").replace("\r", "")
    if "AUTH_FAILED" in out:
        raise RuntimeError("authentification API refusee (identifiants wazuh-wui incorrects)")
    if proc.returncode not in (0, None) and not out.strip():
        raise RuntimeError(f"echec WSL code {proc.returncode} : {(proc.stderr or '').strip()[:200]}")
    return out


def _section(raw: str, start: str, end: str) -> str:
    try:
        return raw.split(start, 1)[1].split(end, 1)[0].strip()
    except IndexError:
        return ""


def run_cyber_task(payload: str) -> tuple[bool, str]:
    raw = _wsl_run(_build_script(*_creds()))
    agents_json = _section(raw, MARK_AGENTS, MARK_ALERTS)
    alerts_json = _section(raw, MARK_ALERTS, MARK_INV)
    inv = _section(raw, MARK_INV, "\x00").strip()

    if not agents_json:
        return False, "le manager n'a renvoye aucune liste d'agents"

    agents = json.loads(agents_json)["data"]["affected_items"]
    alerts = json.loads(alerts_json) if alerts_json else {}
    total_alerts = alerts.get("hits", {}).get("total", {}).get("value", 0)
    levels = {b["key"]: b["doc_count"] for b in alerts.get("aggregations", {}).get("lvl", {}).get("buckets", [])}

    # Un index d'inventaire se termine par -<nom d'agent> : on regarde agent par agent,
    # sinon l'inventaire du manager ferait croire que le parc est couvert.
    inv_indices = [l.strip() for l in inv.splitlines() if l.strip()]

    print(f"  agents enregistres : {len(agents)}")
    actifs = deco = 0
    assets = [a for a in agents if a.get("id") != "000"]
    couverts = 0
    for a in agents:
        st = a.get("status", "?")
        actifs += st == "active"
        deco += st != "active"
        keep = (a.get("lastKeepAlive") or "")[:19]
        ver = (a.get("version") or "").replace("Wazuh ", "").lstrip("v")
        has_inv = any(i.endswith(f"-{a['name']}") for i in inv_indices)
        couverts += has_inv
        print(f"    id={a['id']:<4} {a['name']:<16} {st:<13} keepalive={keep}  v{ver}"
              f"  inventaire={'oui' if has_inv else 'NON'}")
    print(f"  alertes 24 h : {total_alerts}  repartition niveaux : {levels or 'aucune'}")

    sans_inv = [a["name"] for a in assets if not any(i.endswith(f"-{a['name']}") for i in inv_indices)]
    if sans_inv:
        etat_inv = f"syscollector absent pour : {', '.join(sans_inv)}"
    else:
        etat_inv = "syscollector alimente pour tous les actifs"

    msg = (f"{len(agents)} agent(s), {actifs} actif(s), {deco} hors ligne, "
           f"{total_alerts} alertes/24h, {etat_inv}")
    return (deco == 0 and not sans_inv), msg
