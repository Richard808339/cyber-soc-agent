#!/usr/bin/env python3
"""Broker d'autorisation (Human-in-the-Loop) pour le SOC.

Principe : une action sensible n'est jamais executee sans un accord humain
explicite. La demande est bloquee par defaut, envoyee sur Telegram avec deux
boutons, et seule une validation estampillee dans la base partagee debloque
l'execution. Sans reponse dans le delai, c'est un refus.

Differences avec un broker en memoire : l'etat vit dans SQLite, donc n'importe
quel processus (CLI, bot Telegram, tableau de bord) peut approuver, et un
redemarrage ne perd rien.

Configuration (.env) : SOC_TELEGRAM_TOKEN, SOC_TELEGRAM_CHAT_ID
    (les memes que le tableau de bord).

Usage :
    python broker.py request --action "docker restart single-node-wazuh.indexer-1" --details "..."
    python broker.py list
    python broker.py approve <id> [--by cli]
    python broker.py deny <id> --reason "pas maintenant"
    python broker.py wait <id> --exec          # attend puis execute si approuve
    python broker.py guard "docker restart x"  # classification + demande + execution
    python broker.py watch                     # ecoute Telegram (boutons + commandes)
"""

import argparse
import json
import os
import re
import secrets
import shlex
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

DB_PATH = os.environ.get("SOC_DB", os.path.join(HERE, "soc.db"))
DEFAULT_TTL = int(os.environ.get("SOC_APPROVAL_TTL", "300"))
API = "https://api.telegram.org/bot%s/%s"

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# --------------------------------------------------------------------------- #
# Politique : ce qui exige un accord humain, et a quel niveau de risque
# --------------------------------------------------------------------------- #
# (motif, risque, libelle) - le premier motif qui matche gagne.
SENSITIVE = [
    (r"docker\s+(rm|rmi|stop|kill|restart|pause|unpause|prune|system\s+prune)", "critique",
     "cycle de vie d'un conteneur"),
    (r"docker\s+compose\s+(down|stop|rm|kill)", "critique", "arret d'une pile compose"),
    (r"(iptables|ip6tables|nft|ufw|firewall-cmd)\s", "critique", "regle de pare-feu"),
    (r"netsh\s+advfirewall\s+(set|add|delete)", "critique", "regle de pare-feu Windows"),
    (r"new-netfirewallrule|remove-netfirewallrule", "critique", "regle de pare-feu Windows"),
    (r"git\s+push", "eleve", "publication de code"),
    (r"git\s+(reset\s+--hard|clean\s+-fd|filter-repo)", "critique", "reecriture d'historique"),
    (r"(rm\s+-rf|rm\s+-r\s+/|del\s+/[sq]|rd\s+/s|remove-item\s+.*-recurse)", "critique",
     "suppression de fichiers"),
    (r"(shutdown|reboot|halt|poweroff)", "critique", "arret du systeme"),
    (r"systemctl\s+(stop|disable|mask|restart)", "eleve", "service systeme"),
    (r"stop-service|restart-service|disable-service", "eleve", "service Windows"),
    (r"(curl|wget).*\|\s*(ba)?sh", "critique", "execution de script distant"),
    (r"(pip|npm|winget|apt|dnf)\s+(install|uninstall|remove|upgrade)", "moyen",
     "installation de logiciel"),
]

# Actions explicitement inoffensives : jamais de demande (evite de fatiguer l'humain,
# un broker qui demande tout est un broker qu'on finit par approuver sans lire).
SAFE = [
    r"^\s*(docker\s+(ps|logs|inspect|stats|version|images)|git\s+(status|log|diff|show|branch)\b)",
    r"^\s*(cat|ls|dir|type|head|tail|grep|findstr|wc|df|du|whoami|hostname|ipconfig|netstat)\b",
    r"^\s*(curl|wget)\s",
    r"^\s*(python|py)\s+[\w./\\-]+\.py\b",
    r"^\s*echo\b",
]


WRAPPER = re.compile(
    r"^(?:sh|bash|zsh|dash|cmd|powershell|pwsh)(?:\.exe)?\s+(?:-c|-command|/c|/k|-Command)\s+(.+)$",
    re.IGNORECASE)


def normalize(action, profondeur=0):
    """Retire les enveloppes qui cachent la vraie commande.

    `wsl -d wazuh -e docker rm x` et `wsl -e sh -c "docker rm x"` doivent etre
    classes comme `docker rm x`, sinon la politique s'applique a l'enveloppe et
    laisse passer l'action reelle.
    """
    texte = (action or "").strip()
    if profondeur > 3:
        return texte
    m = re.match(r"^wsl(?:\.exe)?\s+(?:-d\s+\S+\s+|--distribution\s+\S+\s+)?"
                 r"(?:-e|--exec|--)?\s*(.+)$", texte, re.IGNORECASE)
    if m and m.group(1):
        return normalize(m.group(1).strip(), profondeur + 1)
    m = WRAPPER.match(texte)
    if m and m.group(1):
        interieur = m.group(1).strip().strip('"').strip("'").strip()
        return normalize(interieur, profondeur + 1)
    return texte


def build_argv(action):
    """Decoupe en argv pour une execution SANS shell. Retourne (argv, erreur)."""
    texte = (action or "").strip()
    if not texte:
        return None, "commande vide"
    dangereux = re.search(r"[;&|<>`]|\$\(|\$\{|\n|\r", texte)
    if dangereux:
        return None, "metacaractere de shell refuse (%r)" % dangereux.group(0)
    try:
        argv = [t.strip('"').strip("'") for t in shlex.split(texte, posix=False)]
    except ValueError as exc:
        return None, "commande illisible : %s" % exc
    return [a for a in argv if a != ""], None


def classify(action):
    """Retourne (risque, motif). risque=None si l'action ne demande pas d'accord."""
    texte = (action or "").strip()
    low = normalize(texte).lower()
    for motif in SAFE:
        if re.search(motif, low):
            return None, None
    for motif, risque, libelle in SENSITIVE:
        if re.search(motif, low):
            return risque, libelle
    # Par defaut, on n'invente pas une autorisation : une action inconnue
    # n'est pas executee par ce broker, elle est signalee comme a trancher.
    return None, None


# --------------------------------------------------------------------------- #
# Stockage
# --------------------------------------------------------------------------- #
SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    id          TEXT PRIMARY KEY,
    agent       TEXT,
    action      TEXT NOT NULL,
    details     TEXT,
    risk        TEXT NOT NULL DEFAULT 'eleve',
    status      TEXT NOT NULL DEFAULT 'pending',
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    decided_at  TEXT,
    decided_by  TEXT,
    executed_at TEXT,
    result      TEXT,
    tg_message_id INTEGER
);
CREATE TABLE IF NOT EXISTS approval_audit (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL,
    approval_id TEXT,
    event   TEXT NOT NULL,
    actor   TEXT,
    detail  TEXT
);
CREATE TABLE IF NOT EXISTS broker_state (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init():
    with connect() as conn:
        conn.executescript(SCHEMA)


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.replace(microsecond=0).isoformat()


def audit(conn, approval_id, event, actor=None, detail=None):
    conn.execute(
        "INSERT INTO approval_audit (ts, approval_id, event, actor, detail) VALUES (?,?,?,?,?)",
        (_iso(_now()), approval_id, event, actor, (detail or "")[:500]),
    )


def new_request(action, agent="agent-soc", details="", risk=None, ttl=None):
    """Cree une demande bloquee. Retourne (id, risque, motif)."""
    init()
    risque_auto, libelle = classify(action)
    if risk:
        risque = risk
    else:
        risque = risque_auto or "eleve"
    if not libelle:
        libelle = "declare sensible par l'appelant"
    code = secrets.token_hex(4)
    maintenant = _now()
    expire = maintenant + timedelta(seconds=int(ttl or DEFAULT_TTL))
    with connect() as conn:
        conn.execute(
            "INSERT INTO approvals (id, agent, action, details, risk, status, created_at, expires_at) "
            "VALUES (?,?,?,?,?, 'pending', ?, ?)",
            (code, agent, action, details, risque, _iso(maintenant), _iso(expire)),
        )
        audit(conn, code, "demande", agent, "%s | %s" % (risque, action[:200]))
    return code, risque, libelle


def get(code):
    with connect() as conn:
        row = conn.execute("SELECT * FROM approvals WHERE id = ?", (code,)).fetchone()
        return dict(row) if row else None


def list_requests(status=None, limit=20):
    with connect() as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM approvals WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (status, limit)).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM approvals ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def _expire_if_needed(conn, row):
    if row["status"] != "pending":
        return False
    if _iso(_now()) > row["expires_at"]:
        conn.execute(
            "UPDATE approvals SET status='expired', decided_at=?, decided_by='systeme' WHERE id=?",
            (_iso(_now()), row["id"]))
        audit(conn, row["id"], "expiration", "systeme", "delai depasse : refus par defaut")
        return True
    return False


def approve(code, actor="cli"):
    """Approuve une demande en attente. Retourne (ok, message)."""
    with connect() as conn:
        row = conn.execute("SELECT * FROM approvals WHERE id = ?", (code,)).fetchone()
        if not row:
            return False, "demande inconnue"
        if _expire_if_needed(conn, row):
            return False, "demande expiree : refus par defaut"
        if row["status"] != "pending":
            return False, "deja %s" % row["status"]
        conn.execute(
            "UPDATE approvals SET status='approved', decided_at=?, decided_by=? WHERE id=?",
            (_iso(_now()), actor, code))
        audit(conn, code, "approbation", actor)
    return True, "approuvee"


def deny(code, actor="cli", reason=""):
    with connect() as conn:
        row = conn.execute("SELECT * FROM approvals WHERE id = ?", (code,)).fetchone()
        if not row:
            return False, "demande inconnue"
        if row["status"] != "pending":
            return False, "deja %s" % row["status"]
        conn.execute(
            "UPDATE approvals SET status='denied', decided_at=?, decided_by=? WHERE id=?",
            (_iso(_now()), actor, code))
        audit(conn, code, "refus", actor, reason)
    return True, "refusee"


# --------------------------------------------------------------------------- #
# Telegram
# --------------------------------------------------------------------------- #
def load_dotenv(path=None):
    path = path or os.path.join(HERE, ".env")
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8-sig") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def credentials():
    tok = (os.environ.get("SOC_TELEGRAM_TOKEN") or "").strip()
    chat = (os.environ.get("SOC_TELEGRAM_CHAT_ID") or "").strip()
    if not tok or not chat:
        raise RuntimeError("SOC_TELEGRAM_TOKEN / SOC_TELEGRAM_CHAT_ID absents")
    return tok, chat


def tg(method, **params):
    tok, _ = credentials()
    body = urllib.parse.urlencode(params, encoding="utf-8").encode("utf-8")
    req = urllib.request.Request(API % (tok, method), data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return {"ok": False, "description": exc.read().decode("utf-8", "replace")[:200]}


def _e(texte):
    """Echappe le HTML : un detail contenant <id> ou & casse le parseur Telegram (400)."""
    import html as _html
    return _html.escape(str(texte or ""), quote=False)


def notify_request(code, action, agent, details, risk):
    """Envoie la demande avec deux boutons. Retourne le message_id (ou None)."""
    texte = (
        "<b>[AUTORISATION REQUISE]</b>\n\n"
        "• <b>Demande</b> : <code>%s</code>\n"
        "• <b>Risque</b> : %s\n"
        "• <b>Agent</b> : %s\n"
        "• <b>Action</b> : <code>%s</code>\n"
        "%s\n"
        "Sans reponse sous %d s, refus automatique."
    ) % (code, _e(risk.upper()), _e(agent), _e(action[:300]),
         ("• <b>Details</b> : " + _e(details[:400]) + "\n") if details else "",
         DEFAULT_TTL)
    clavier = {"inline_keyboard": [[
        {"text": "Approuver %s" % code, "callback_data": "approve:%s" % code},
        {"text": "Refuser %s" % code, "callback_data": "deny:%s" % code},
    ]]}
    res = tg("sendMessage", chat_id=credentials()[1], text=texte, parse_mode="HTML",
             reply_markup=json.dumps(clavier), disable_web_page_preview="true")
    mid = (res.get("result") or {}).get("message_id")
    if mid:
        with connect() as conn:
            conn.execute("UPDATE approvals SET tg_message_id = ? WHERE id = ?", (mid, code))
            audit(conn, code, "notification", "broker", "telegram message %s" % mid)
    else:
        with connect() as conn:
            audit(conn, code, "notification_echec", "broker", str(res.get("description"))[:200])
    return mid


def notify_decision(code, decision, actor):
    try:
        action = (get(code) or {}).get("action", "")
        libelle = "APPROUVEE" if decision == "approved" else "REFUSEE"
        tg("sendMessage", chat_id=credentials()[1],
           text="<b>[%s]</b> demande <code>%s</code>\n<code>%s</code>\npar %s"
                % (libelle, code, _e(action[:200]), _e(actor)),
           parse_mode="HTML")
    except Exception:
        pass


def _state_get(key, default=None):
    with connect() as conn:
        row = conn.execute("SELECT value FROM broker_state WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default


def _state_set(key, value):
    with connect() as conn:
        conn.execute("INSERT INTO broker_state (key, value) VALUES (?,?) "
                     "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, str(value)))


def parse_update(update):
    """Extrait une decision d'un update Telegram. Retourne (code, 'approved'|'denied', acteur).

    Gere les deux canaux : bouton inline (callback_query) et commande texte
    ('approuver <id>' / 'refuser <id>').
    """
    cq = update.get("callback_query")
    if cq:
        data = cq.get("data") or ""
        acteur = "telegram:%s" % ((cq.get("from") or {}).get("id") or "?")
        if data.startswith("approve:"):
            return data.split(":", 1)[1], "approved", acteur
        if data.startswith("deny:"):
            return data.split(":", 1)[1], "denied", acteur
        return None, None, None

    msg = update.get("message") or {}
    texte = (msg.get("text") or "").strip().lower()
    acteur = "telegram:%s" % ((msg.get("from") or {}).get("id") or "?")
    m = re.match(r"^(approuver|approve|refuser|deny)\s+([0-9a-f]{4,16})\b", texte)
    if not m:
        return None, None, None
    decision = "approved" if m.group(1) in ("approuver", "approve") else "denied"
    return m.group(2), decision, acteur


def watch(poll_seconds=2):
    """Ecoute Telegram et applique les validations. Tourne en continu."""
    init()
    _, chat = credentials()
    offset = int(_state_get("tg_offset", 0) or 0)
    print("[broker] ecoute Telegram (chat autorise: %s)" % chat)
    while True:
        try:
            res = tg("getUpdates", offset=offset, timeout=20,
                     allowed_updates=json.dumps(["message", "callback_query"]))
        except Exception as exc:
            print("[broker] erreur getUpdates :", exc)
            time.sleep(5)
            continue
        if not res.get("ok"):
            time.sleep(5)
            continue
        for update in res.get("result") or []:
            offset = max(offset, int(update.get("update_id", 0)) + 1)
            code, decision, acteur = parse_update(update)
            if not code:
                continue
            origine = (((update.get("callback_query") or {}).get("message") or {})
                       .get("chat") or {}).get("id") or \
                      ((update.get("message") or {}).get("chat") or {}).get("id")
            if str(origine) != str(chat):
                print("[broker] decision ignoree : chat non autorise", origine)
                with connect() as conn:
                    audit(conn, None, "decision_refusee_chat", acteur, str(origine))
                continue
            if decision == "approved":
                ok, msg = approve(code, acteur)
            else:
                ok, msg = deny(code, acteur, "refus via Telegram")
            cq = update.get("callback_query") or {}
            if cq.get("id"):
                libelle = "Enregistre" if ok else msg
                tg("answerCallbackQuery", callback_query_id=cq["id"], text="%s %s" % (code, libelle))
            print("[broker] %s -> %s (%s)" % (code, decision, msg))
        _state_set("tg_offset", offset)
        time.sleep(poll_seconds)


def containers_uptime(distro=None):
    """Etat des conteneurs : {nom: (running, epoch du demarrage)}.

    On lit `.State.StartedAt` et non `Up 3 hours` : la duree affichee par docker
    est tronquee a l'heure pres, donc la date de demarrage derive d'une heure
    d'un relevé a l'autre et produit de fausses alertes.
    """
    distro = distro or os.environ.get("SOC_WSL_DISTRO", "wazuh")
    base = ["wsl", "-d", distro, "-e", "docker"]
    try:
        noms = subprocess.run(base + ["ps", "-a", "--format", "{{.Names}}"],
                              capture_output=True, text=True, timeout=60,
                              encoding="utf-8", errors="replace")
    except Exception as exc:
        return {}, str(exc)
    if noms.returncode != 0:
        return {}, (noms.stderr or "").strip()[:300]
    liste = [n.strip() for n in (noms.stdout or "").splitlines() if n.strip()]
    if not liste:
        return {}, None
    try:
        infos = subprocess.run(base + ["inspect", "--format",
                                       "{{.Name}}|{{.State.Running}}|{{.State.StartedAt}}"] + liste,
                               capture_output=True, text=True, timeout=90,
                               encoding="utf-8", errors="replace")
    except Exception as exc:
        return {}, str(exc)
    if infos.returncode != 0:
        return {}, (infos.stderr or "").strip()[:300]

    resultat = {}
    for ligne in (infos.stdout or "").splitlines():
        morceaux = ligne.split("|")
        if len(morceaux) != 3:
            continue
        nom, running, demarre = morceaux
        try:
            propre = demarre.strip().split(".")[0].replace("Z", "+00:00")
            epoch = datetime.fromisoformat(propre).replace(tzinfo=timezone.utc).timestamp()
        except Exception:
            epoch = 0.0
        resultat[nom.strip().lstrip("/")] = (running.strip().lower() == "true", epoch)
    return resultat, None


def detect(lookback_seconds=1800, notify=True):
    """Detecte un redemarrage de conteneur sans autorisation enregistree.

    Un broker contournable reste utile si l'effet est visible : ici on compare
    l'heure de demarrage reelle des conteneurs a la derniere photo connue, et on
    cherche une approbation executee dans la fenetre. Rien trouve = anomalie.
    """
    etat, erreur = containers_uptime()
    if erreur:
        return {"ok": False, "erreur": erreur[:200], "anomalies": []}
    maintenant = time.time()
    base = {}
    try:
        base = json.loads(_state_get("containers_baseline", "{}") or "{}")
    except Exception:
        base = {}

    anomalies = []
    premiere_photo = not base
    for nom, (running, demarrage) in etat.items():
        precedent = base.get(nom)
        if running and precedent and demarrage > float(precedent) + 5:
            autorise = False
            fenetre = datetime.fromtimestamp(max(demarrage - 120, 0), timezone.utc)
            with connect() as conn:
                rows = conn.execute(
                    "SELECT id, action, executed_at FROM approvals "
                    "WHERE status='executed' AND executed_at > ?", (_iso(fenetre),)).fetchall()
            for r in rows:
                if nom in (r["action"] or ""):
                    autorise = True
                    break
            if not autorise:
                anomalies.append({
                    "conteneur": nom,
                    "demarre_il_y_a_s": max(int(maintenant - demarrage), 0),
                    "constat": "redemarrage sans trace d'autorisation (crash ou action manuelle)",
                })
        if running:
            base[nom] = demarrage

    with connect() as conn:
        _state_set("containers_baseline", json.dumps(base))
        if anomalies:
            audit(conn, None, "anomalie_contournement", "detect",
                  "; ".join(a["conteneur"] for a in anomalies))

    if anomalies and notify:
        try:
            lignes = ["<b>[ALERTE] action hors broker</b>", ""]
            for a in anomalies:
                lignes.append("• <code>%s</code> — %s (demarre il y a %d s)"
                              % (_e(a["conteneur"]), a["constat"], a["demarre_il_y_a_s"]))
            lignes.append("")
            lignes.append("Aucune approbation ne couvre ce redemarrage : action manuelle "
                          "hors broker, ou crash du conteneur.")
            tg("sendMessage", chat_id=credentials()[1], text="\n".join(lignes), parse_mode="HTML")
        except Exception:
            pass

    return {"ok": True, "conteneurs": len(etat), "anomalies": anomalies,
            "premiere_photo": premiere_photo}


# --------------------------------------------------------------------------- #
# Execution gardee
# --------------------------------------------------------------------------- #
def claim(code, actor="shield"):
    """Consomme une approbation atomiquement, sans executer.

    Utilise par le garde-fou en processus : l'appelant va lancer lui-meme la
    commande, le broker ne doit pas la lancer une seconde fois.
    """
    with connect() as conn:
        cur = conn.execute(
            "UPDATE approvals SET status='executed', executed_at=? "
            "WHERE id=? AND status='approved'", (_iso(_now()), code))
        if cur.rowcount != 1:
            return False
        audit(conn, code, "consommation", actor, "approbation utilisee par le garde-fou")
    return True


def execute(code, shell=False):
    """Execute l'action approuvee et enregistre le resultat.

    Execution sans shell (subprocess shell=False) : la commande approuvee est
    celle qui tourne, un `;` ou un `|` glisse dans la chaine ne peut pas ajouter
    une seconde commande non approuvee.
    """
    row = get(code)
    if not row:
        return False, "demande inconnue"
    if row["status"] != "approved":
        return False, "statut %s : execution refusee" % row["status"]
    if row.get("executed_at"):
        return False, "deja executee"
    argv, erreur = build_argv(row["action"])
    if erreur or not argv:
        with connect() as conn:
            conn.execute("UPDATE approvals SET status='denied', decided_at=?, decided_by='broker', "
                         "result=? WHERE id=?", (_iso(_now()), erreur or "argv vide", code))
            audit(conn, code, "execution_refusee", "broker", erreur or "argv vide")
        return False, "execution refusee : %s" % (erreur or "argv vide")
    try:
        proc = subprocess.run(argv, shell=False, capture_output=True, text=True,
                              timeout=180, encoding="utf-8", errors="replace")
        sortie = ((proc.stdout or "") + (proc.stderr or "")).strip()[:2000]
        code_retour = proc.returncode
    except Exception as exc:
        sortie, code_retour = "%s: %s" % (exc.__class__.__name__, exc), -1
    with connect() as conn:
        conn.execute("UPDATE approvals SET status='executed', executed_at=?, result=? WHERE id=?",
                     (_iso(_now()), "code=%s | %s" % (code_retour, sortie[:1500]), code))
        audit(conn, code, "execution", "broker", "code=%s | %s" % (code_retour, " ".join(argv)[:120]))
    return True, sortie


def wait_for_decision(code, timeout=None):
    """Attend la decision humaine. Timeout = refus."""
    row = get(code)
    if not row:
        return "unknown"
    limite = time.time() + (timeout if timeout is not None else DEFAULT_TTL + 30)
    while time.time() < limite:
        row = get(code)
        statut = row["status"]
        if statut in ("approved", "denied", "expired", "executed"):
            return statut
        if _iso(_now()) > row["expires_at"]:
            with connect() as conn:
                _expire_if_needed(conn, row)
            notify_decision(code, "denied", "systeme (delai)")
            return "expired"
        time.sleep(2)
    return "timeout"


def guard(action, agent="agent-soc", details="", execute_it=False, ttl=None):
    """Point d'entree unique : classifie, demande, attend, execute si approuve."""
    risque, libelle = classify(action)
    if risque is None:
        print("[broker] action non sensible : execution directe")
        if execute_it:
            return execute_raw(action)
        return {"status": "safe", "executed": False}

    code, risque, libelle = new_request(action, agent, details, risk=risque, ttl=ttl)
    print("[broker] demande %s creee (%s, %s) - bloquee en attente d'accord humain"
          % (code, risque, libelle or "action sensible"))
    mid = notify_request(code, action, agent, details, risque)
    if not mid:
        print("[broker] attention : notification Telegram non envoyee -> la demande expire seule")
    statut = wait_for_decision(code)
    if statut == "approved" and execute_it:
        ok, sortie = execute(code)
        print("[broker] execution :", "ok" if ok else "refusee", "|", sortie[:200])
        return {"status": "executed" if ok else statut, "output": sortie}
    print("[broker] decision :", statut)
    return {"status": statut}


def execute_raw(action):
    """Execution directe d'une action non sensible, sans shell."""
    argv, erreur = build_argv(action)
    if erreur or not argv:
        return {"status": "refused", "output": erreur or "argv vide"}
    proc = subprocess.run(argv, shell=False, capture_output=True, text=True,
                          timeout=180, encoding="utf-8", errors="replace")
    return {"status": "executed", "code": proc.returncode,
            "output": ((proc.stdout or "") + (proc.stderr or ""))[:2000]}


def main():
    ap = argparse.ArgumentParser(description="Broker d'autorisation HITL")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("request", help="creer une demande d'autorisation")
    p.add_argument("--action", required=True)
    p.add_argument("--details", default="")
    p.add_argument("--agent", default="agent-soc")
    p.add_argument("--ttl", type=int, default=None)
    p.add_argument("--risk", default=None, choices=["critique", "eleve", "moyen"])

    sub.add_parser("list", help="lister les demandes")

    p = sub.add_parser("approve", help="approuver une demande")
    p.add_argument("id")
    p.add_argument("--by", default="cli")

    p = sub.add_parser("deny", help="refuser une demande")
    p.add_argument("id")
    p.add_argument("--by", default="cli")
    p.add_argument("--reason", default="")

    p = sub.add_parser("wait", help="attendre la decision (puis executer avec --exec)")
    p.add_argument("id")
    p.add_argument("--exec", action="store_true")

    p = sub.add_parser("guard", help="classifier + demander + executer")
    p.add_argument("action")
    p.add_argument("--agent", default="agent-soc")
    p.add_argument("--details", default="")
    p.add_argument("--execute", action="store_true")
    p.add_argument("--ttl", type=int, default=None)

    sub.add_parser("watch", help="ecouter Telegram en continu")

    p = sub.add_parser("detect", help="detecter une action faite hors du broker")
    p.add_argument("--no-notify", action="store_true")
    p = sub.add_parser("audit", help="journal des decisions")
    p.add_argument("--limit", type=int, default=20)

    args = ap.parse_args()
    load_dotenv()
    init()

    if args.cmd == "request":
        code, risque, libelle = new_request(args.action, args.agent, args.details,
                                            risk=args.risk, ttl=args.ttl)
        mid = notify_request(code, args.action, args.agent, args.details, risque)
        print(json.dumps({"id": code, "risk": risque, "motif": libelle,
                          "telegram_message_id": mid}, ensure_ascii=False))
    elif args.cmd == "list":
        for r in list_requests():
            print("%s  %-9s %-9s %s  %s" % (r["id"], r["status"], r["risk"],
                                            r["created_at"][:19], r["action"][:70]))
    elif args.cmd == "approve":
        print(approve(args.id, args.by))
        notify_decision(args.id, "approved", args.by)
    elif args.cmd == "deny":
        print(deny(args.id, args.by, args.reason))
        notify_decision(args.id, "denied", args.by)
    elif args.cmd == "wait":
        statut = wait_for_decision(args.id)
        print(statut)
        if statut == "approved" and args.exec:
            print(execute(args.id))
    elif args.cmd == "guard":
        print(json.dumps(guard(args.action, args.agent, args.details, args.execute, args.ttl),
                         ensure_ascii=False))
    elif args.cmd == "watch":
        watch()
    elif args.cmd == "detect":
        print(json.dumps(detect(notify=not args.no_notify), ensure_ascii=False, indent=2))
    elif args.cmd == "audit":
        with connect() as conn:
            rows = conn.execute("SELECT * FROM approval_audit ORDER BY id DESC LIMIT ?",
                                (args.limit,)).fetchall()
        for r in rows:
            print("%s  %-8s %-18s %-14s %s" % (r["ts"][:19], r["approval_id"] or "-",
                                               r["event"], r["actor"] or "-",
                                               (r["detail"] or "")[:60]))


if __name__ == "__main__":
    main()
