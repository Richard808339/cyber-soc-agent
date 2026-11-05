#!/usr/bin/env python3
"""Tableau de bord SOC — serveur HTTP (bibliotheque standard, zero dependance).

Architecture (contrainte : Wazuh tourne en local, pas joignable depuis Internet) :
    Wazuh (local) --collector.py--> POST /api/ingest --> SQLite --> ce serveur --> navigateur

Le tableau de bord ne parle jamais a Wazuh : il ne lit que ce que le collecteur
a pousse. On peut donc l'heberger ailleurs sans exposer le manager.

Lancement : python app.py [--port 8765] [--bind 127.0.0.1]
"""

import argparse
import base64
import hmac
import ipaddress
import json
import math
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import playbooks  # noqa: E402
import notifier  # noqa: E402
import socstore  # noqa: E402
import summarizer  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

STATIC_DIR = os.path.join(HERE, "static")
MAX_BODY = 8 * 1024 * 1024

# Table figee des types servis : le Content-Type ne depend jamais de la requete.
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".txt": "text/plain; charset=utf-8",
}
SUMMARY_TTL_SECONDS = int(os.environ.get("SOC_SUMMARY_TTL", "600"))
# Intervalle minimal entre deux regenerations automatiques (evite d'appeler le LLM a chaque collecte).
SUMMARY_MIN_INTERVAL = int(os.environ.get("SOC_SUMMARY_MIN_INTERVAL", "120"))


def load_dotenv():
    path = os.path.join(HERE, ".env")
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _age_seconds(iso_ts):
    if not iso_ts:
        return None
    try:
        ts = iso_ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int((datetime.now(timezone.utc) - dt).total_seconds())
    except Exception:
        return None


def _summary_is_stale(last, snapshot, force=False):
    """Un bilan est perime s'il a ete redige sur des donnees plus anciennes que le
    dernier snapshot recu, ou s'il depasse le TTL. Un intervalle minimal evite les
    regenerations en rafale (et les appels LLM repetes)."""
    if force or not last:
        return True
    s_age = _age_seconds(last.get("generated_at"))
    d_age = _age_seconds((snapshot or {}).get("collected_at"))
    if s_age is None or d_age is None:
        return True
    if s_age > SUMMARY_TTL_SECONDS:
        return True
    # Bilan anterieur aux donnees courantes : il ne decrit plus la situation.
    if s_age > d_age + 5 and s_age >= SUMMARY_MIN_INTERVAL:
        return True
    return False


def static_path(rel):
    """Resout un chemin sous static/ et refuse toute sortie du dossier.

    Retourne None si le chemin demande sort de STATIC_DIR apres normalisation
    (traversee par '..' ou par encodage %2e%2e).
    """
    rel = urllib.parse.unquote(rel).replace("\\", "/").lstrip("/")
    if not rel:
        return None
    root = os.path.realpath(STATIC_DIR)
    candidate = os.path.realpath(os.path.join(root, rel))
    if candidate == root or not candidate.startswith(root + os.sep):
        return None
    return candidate


LAB_TIMEOUT = float(os.environ.get("SOC_LAB_TIMEOUT", "3"))


def lab_snapshot():
    """Etat du reseau d'agents, lu aupres de l'orchestrateur local.

    Le navigateur ne peut pas appeler l'orchestrateur directement (autre port,
    pas de CORS) : on relaie ici, et on ne garde que des champs d'affichage.
    """
    base = os.environ.get("ORCHESTRATOR_URL", "http://127.0.0.1:8000").rstrip("/")
    key = os.environ.get("ORCH_KEY", "LAB-ORCH-SECRET")
    out = {"available": False, "agents": [], "tasks": [], "tasks_total": 0,
           "tasks_running": 0, "error": None}

    def get(path):
        request = urllib.request.Request(base + path, headers={"X-Orchestrator-Key": key})
        with urllib.request.urlopen(request, timeout=LAB_TIMEOUT) as response:
            return json.loads(response.read() or b"{}")

    try:
        health = get("/health")
        data = get("/agents")
        agents = data.get("agents", data) if isinstance(data, dict) else data
        tasks = get("/tasks?limit=8")
        tasks = tasks.get("tasks", tasks) if isinstance(tasks, dict) else tasks
        out.update({
            "available": True,
            "agents": [{k: a.get(k) for k in ("agent_id", "name", "status", "endpoint",
                                              "capabilities", "last_seen")} for a in agents],
            "tasks": [{k: t.get(k) for k in ("task_id", "capability", "agent_id", "status",
                                             "duration_ms", "created_at")} for t in tasks],
            "tasks_total": health.get("tasks", 0),
            "tasks_running": sum(1 for t in tasks
                                 if t.get("status") in ("RUNNING", "PENDING", "QUEUED")),
        })
    except Exception as exc:  # noqa: BLE001 - l'orchestrateur peut etre arrete
        out["error"] = "orchestrateur injoignable (%s)" % type(exc).__name__
    return out


def _tcp_ouvert(port, hote="127.0.0.1", delai=0.4):
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(delai)
        return s.connect_ex((hote, port)) == 0


def _ecoutes_publiques():
    """Ports en LISTEN sur 0.0.0.0, lus dans netstat. Liste vide si indisponible."""
    try:
        res = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True,
                             text=True, errors="replace", timeout=10)
    except Exception:
        return []
    ports = set()
    for ligne in (res.stdout or "").splitlines():
        morceaux = ligne.split()
        if len(morceaux) < 4 or "LISTEN" not in ligne.upper():
            continue
        local = morceaux[1]
        if local.startswith("0.0.0.0:"):
            try:
                ports.add(int(local.rsplit(":", 1)[1]))
            except ValueError:
                pass
    return sorted(ports)


def is_loopback_bind(host):
    try:
        return ipaddress.ip_address(str(host).strip("[]")).is_loopback
    except ValueError:
        return str(host).lower() in ("localhost",)


class Handler(BaseHTTPRequestHandler):
    server_version = "SocDashboard/1.0"

    # ------------------------------------------------------------------ utils
    def _send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path):
        if not path or not os.path.isfile(path):
            return self._send_json({"error": "introuvable"}, 404)
        # Type MIME issu d'une table figee : aucune valeur derivee de la requete
        # n'atteint l'en-tete (pas d'injection CRLF, pas de backtracking regex).
        ctype = CONTENT_TYPES.get(os.path.splitext(path)[1].lower(), "application/octet-stream")
        with open(path, "rb") as fh:
            data = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _read_token(self):
        auth = self.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return self.headers.get("X-SOC-Token") or ""

    def _token_ok(self, expected):
        got = self._read_token()
        if not expected:
            return True
        return bool(got) and hmac.compare_digest(got, expected)

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY:
            raise ValueError("corps trop volumineux")
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    # ------------------------------------------------------------------ routes
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            return self._send_file(os.path.join(STATIC_DIR, "index.html"))

        if path.startswith("/static/"):
            resolved = static_path(path[len("/static/"):])
            if resolved is None:
                return self._send_json({"error": "chemin refuse"}, 403)
            return self._send_file(resolved)

        if path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return

        if not path.startswith("/api/"):
            return self._send_json({"error": "route inconnue"}, 404)

        read_token = os.environ.get("SOC_READ_TOKEN", "").strip()
        if read_token and not self._token_ok(read_token):
            return self._send_json({"error": "jeton de lecture invalide"}, 401)

        try:
            if path == "/api/health":
                snap = socstore.latest_snapshot()
                return self._send_json({
                    "ok": True,
                    "db": socstore.DB_PATH,
                    "has_data": snap is not None,
                    "age_seconds": _age_seconds((snap or {}).get("collected_at")),
                })

            if path == "/api/overview":
                return self._send_json(self._overview())

            if path == "/api/lab/agents":
                return self._send_json(lab_snapshot())

            if path == "/api/alerts":
                level = query.get("level", [None])[0]
                return self._send_json({
                    "alerts": socstore.query_alerts(
                        level_min=int(level) if level not in (None, "", "0") else None,
                        agent=query.get("agent", [None])[0],
                        playbook=query.get("playbook", [None])[0],
                        limit=int(query.get("limit", ["100"])[0]),
                    )
                })

            if path == "/api/playbooks":
                return self._send_json({"playbooks": playbooks.catalog()})

            if path.startswith("/api/playbook/"):
                key = path.rsplit("/", 1)[-1]
                return self._send_json({"key": key, "playbook": playbooks.get(key)})

            if path == "/api/summary":
                refresh = query.get("refresh", ["0"])[0] == "1"
                return self._send_json(self._summary(force=refresh))

            if path == "/api/history":
                return self._send_json({
                    "snapshots": socstore.list_snapshots(int(query.get("limit", ["20"])[0])),
                    "ingest": socstore.ingest_history(10),
                    "alerts": socstore.alert_stats(),
                })

            if path == "/api/redteam":
                return self._send_json(self._redteam())

            return self._send_json({"error": "route inconnue"}, 404)
        except Exception as exc:
            return self._send_json({"error": str(exc), "type": exc.__class__.__name__}, 500)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/ingest":
            expected = os.environ.get("SOC_INGEST_TOKEN", "").strip()
            if expected and not self._token_ok(expected):
                socstore.log_ingest(False, 0, self.client_address[0], "jeton invalide")
                return self._send_json({"error": "jeton d'ingestion invalide"}, 401)
            try:
                payload = self._read_body()
            except Exception as exc:
                socstore.log_ingest(False, 0, self.client_address[0], str(exc))
                return self._send_json({"error": str(exc)}, 400)

            if not payload.get("collected_at"):
                return self._send_json({"error": "champ collected_at obligatoire"}, 400)

            nbytes = socstore.save_snapshot(payload)
            recent = payload.get("recent_alerts") or []
            new_alerts = socstore.save_alerts(recent) if recent else 0
            socstore.log_ingest(
                True, nbytes, self.client_address[0],
                "agents=%d alertes=%d nouvelles=%d" % (
                    len(payload.get("agents") or []), len(recent), new_alerts),
            )

            # Bilan regenere si l'ancien decrit des donnees plus anciennes que celles recues.
            last = socstore.latest_summary()
            if _summary_is_stale(last, payload):
                try:
                    socstore.save_summary(self._build_summary(payload))
                except Exception as exc:
                    print("bilan non genere :", exc)

            # Notification Telegram si un constat grave apparait (jamais bloquant).
            try:
                res = notifier.maybe_notify(payload, summarizer.findings(payload),
                                            os.environ.get("SOC_PUBLIC_URL") or None)
                if res.get("sent"):
                    print("notification Telegram envoyee (message_id=%s)" % res.get("message_id"))
            except Exception as exc:
                print("notification impossible :", exc)

            return self._send_json({
                "ok": True, "bytes": nbytes,
                "alerts_received": len(recent), "alerts_new": new_alerts,
                "received_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }, 202)

        if path == "/api/summary/refresh":
            return self._send_json(self._summary(force=True))

        if path in ("/api/assistant", "/api/reverse"):
            read_token = os.environ.get("SOC_READ_TOKEN", "").strip()
            if read_token and not self._token_ok(read_token):
                return self._send_json({"error": "jeton de lecture invalide"}, 401)
            try:
                payload = self._read_body()
            except Exception as exc:
                return self._send_json({"error": str(exc)}, 400)
            try:
                if path == "/api/assistant":
                    return self._send_json(self._assistant(payload))
                return self._send_json(self._reverse(payload))
            except Exception as exc:
                return self._send_json({"error": str(exc), "type": exc.__class__.__name__}, 400)

        return self._send_json({"error": "route inconnue"}, 404)

    # ------------------------------------------------------------------ vues
    def _overview(self):
        snap = socstore.latest_snapshot()
        if not snap:
            return {"ready": False, "message": "Aucun snapshot. Lancez collector.py pour alimenter le tableau de bord.",
                    "playbooks": playbooks.catalog()}

        metrics = summarizer.compute_metrics(snap)
        alerts = snap.get("alerts") or {}
        stats = socstore.alert_stats()
        last = socstore.latest_summary()
        age = _age_seconds(snap.get("collected_at"))

        return {
            "ready": True,
            "collected_at": snap.get("collected_at"),
            "received_at": snap.get("_received_at"),
            "age_seconds": age,
            "stale": age is None or age > 900,
            "manager": snap.get("manager") or {},
            "collector": snap.get("collector") or {},
            "host": snap.get("host") or {},
            "errors": snap.get("errors") or [],
            "kpi": {
                "agents_active": metrics["agents_active"],
                "agents_total": metrics["agents_total"],
                "alerts_24h": metrics["alerts_24h"],
                "alerts_critique": metrics["alerts_critique"],
                "alerts_eleve": metrics["alerts_eleve"],
                "vulns_total": metrics["vulns_total"],
                "vulns_critique": metrics["vulns_critique"],
                "score": metrics["score"],
            },
            "agents": snap.get("agents") or [],
            "timeline": alerts.get("timeline") or [],
            "by_level": alerts.get("by_level") or {},
            "top_rules": alerts.get("top_rules") or [],
            "top_sources": alerts.get("top_sources") or [],
            "top_mitre": alerts.get("top_mitre") or [],
            "vulnerabilities": snap.get("vulnerabilities") or {},
            "stack": snap.get("stack") or {},
            "network": snap.get("network") or {},
            "findings": summarizer.findings(snap),
            "recent_alerts": socstore.query_alerts(limit=40),
            "alert_bank": stats,
            "summary": {
                "generated_at": (last or {}).get("generated_at"),
                "engine": (last or {}).get("engine"),
                "model": (last or {}).get("model"),
                "text": (last or {}).get("text"),
            },
            "playbooks": playbooks.catalog(),
        }

    def _build_summary(self, snapshot):
        prefer = os.environ.get("SOC_SUMMARY_ENGINE", "auto") != "regles"
        return summarizer.summarize(snapshot, prefer_llm=prefer)

    def _summary(self, force=False):
        snap = socstore.latest_snapshot()
        if not snap:
            return {"ready": False, "message": "Aucun snapshot a resumer."}
        last = socstore.latest_summary()
        if _summary_is_stale(last, snap, force):
            last = socstore.save_summary(self._build_summary(snap))
        return {"ready": True, "summary": last,
                "age_seconds": _age_seconds(last.get("generated_at"))}

    # -------------------------------------------------- assistant et analyses
    def _assistant(self, payload):
        """Question libre sur le snapshot courant. LLM si configure, sinon regles."""
        question = str(payload.get("question") or "").strip()[:1200]
        if not question:
            raise ValueError("question vide")

        snap = socstore.latest_snapshot() or {}
        metrics = summarizer.compute_metrics(snap) if snap else {}
        stats = socstore.alert_stats()
        agents = snap.get("agents") or []
        findings = summarizer.findings(snap) if snap else []
        lab = lab_snapshot()
        lab_agents = lab.get("agents") or []
        online = [a for a in lab_agents if a.get("status") == "ONLINE"]
        age = _age_seconds(snap.get("collected_at"))

        contexte = {
            "metriques": metrics,
            "banque_alertes": stats,
            "collecte": {
                "age_secondes": age,
                "collecte_le": snap.get("collected_at"),
                "erreurs": (snap.get("errors") or [])[:6],
            },
            "postes_wazuh": [
                {"nom": a.get("name"), "statut": a.get("status"), "version": a.get("version")}
                for a in agents[:20]
            ],
            "lab": {"en_ligne": len(online), "total": len(lab_agents),
                    "joignable": lab.get("available"), "taches": lab.get("tasks_total")},
            "constats": [{"titre": f.get("title"), "niveau": f.get("level")} for f in findings[:8]],
            "regles_frequentes": (snap.get("alerts") or {}).get("top_rules", [])[:5],
        }

        if os.environ.get("SOC_LLM_API_KEY", "").strip():
            system = (
                "Tu es analyste SOC. Reponds en francais, uniquement a partir du JSON fourni. "
                "Si une information n'y figure pas, dis-le sans l'inventer. Cite les chiffres exacts. "
                "Reponse courte (120 mots maximum), markdown simple, pas de conclusion morale."
            )
            user = question + "\n\nDONNEES:\n" + json.dumps(contexte, ensure_ascii=False, default=str)[:6000]
            try:
                res = summarizer.llm_chat(system, user)
                return {"answer": res["text"], "engine": "llm", "model": res.get("model")}
            except Exception as exc:
                reponse = self._answer_rules(question, contexte)
                return {"answer": reponse, "engine": "moteur interne",
                        "model": "repli (modele indisponible : %s)" % exc}

        return {"answer": self._answer_rules(question, contexte), "engine": "moteur interne",
                "model": "moteur interne"}

    @staticmethod
    def _answer_rules(question, ctx):
        """Reponses calculees depuis le contexte, sans modele ni reseau."""
        q = question.lower()
        m = ctx.get("metriques") or {}
        stats = ctx.get("banque_alertes") or {}
        coll = ctx.get("collecte") or {}
        lab = ctx.get("lab") or {}
        crit = m.get("alerts_critique", 0)
        eleve = m.get("alerts_eleve", 0)
        total = stats.get("total", 0)

        def bloc(titre, lignes):
            return "## %s\n" % titre + "\n".join("- " + l for l in lignes)

        if any(k in q for k in ("critique", "urgent", "grave", "priorit")):
            lignes = ["%d alerte(s) critique(s) — niveau 12 et plus." % crit,
                      "%d alerte(s) elevee(s) — niveau 8 a 11." % eleve,
                      "Score de posture : %s/100." % m.get("score", "inconnu")]
            if not crit and not eleve:
                lignes.append("Aucune alerte critique ni elevee sur la fenetre courante.")
            return bloc("Priorites", lignes)

        if any(k in q for k in ("agent", "lab", "en ligne", "online", "hors ligne")):
            lignes = ["Lab : %s/%s agents en ligne%s." % (
                lab.get("en_ligne", 0), lab.get("total", 0),
                "" if lab.get("joignable") else " (orchestrateur injoignable)")]
            postes = ctx.get("postes_wazuh") or []
            for p in postes[:6]:
                lignes.append("Poste Wazuh %s : %s." % (p.get("nom"), p.get("statut")))
            if not postes:
                lignes.append("Aucun poste Wazuh remonte dans le dernier snapshot.")
            return bloc("Agents", lignes)

        if any(k in q for k in ("collecte", "muet", "indexeur", "vide", "fraich", "age", "stale")):
            age = coll.get("age_secondes")
            lignes = ["Dernier snapshot : %s (age %s)." % (coll.get("collecte_le") or "aucun", age)]
            errs = coll.get("erreurs") or []
            lignes.append("Erreurs de collecte : %s." % ("; ".join(str(e)[:90] for e in errs) if errs else "aucune"))
            if m.get("alerts_24h", 0) == 0:
                lignes.append("Zero alerte sur 24 h : verifier les conteneurs Wazuh et le keepalive des agents.")
            return bloc("Collecte", lignes)

        if "constat" in q or "probleme" in q or "finding" in q:
            fs = ctx.get("constats") or []
            if not fs:
                return "## Constats\nAucun constat ouvert."
            return bloc("Constats", ["**%s** (%s)" % (f.get("titre"), f.get("niveau")) for f in fs])

        if any(k in q for k in ("alertes", "combien", "volume", "total")):
            return bloc("Volume", [
                "Banque locale : %d alertes." % total,
                "24 h : %d alerte(s) selon le dernier snapshot." % m.get("alerts_24h", 0),
                "Critiques : %d — elevees : %d." % (crit, eleve),
            ])

        if "score" in q or "posture" in q:
            return bloc("Posture", ["Score %s/100. 100 = aucun signal critique ouvert." % m.get("score", "inconnu"),
                                    "Actifs : %s/%s postes." % (m.get("agents_active", 0), m.get("agents_total", 0))])

        return ("## Je reponds depuis le snapshot\n"
                "Sujets couverts : alertes critiques, agents, collecte, constats, volume, posture.\n"
                "Chiffres disponibles : %d alertes en banque, %d sur 24 h, score %s/100, "
                "%s/%s agents du lab en ligne." % (
                    total, m.get("alerts_24h", 0), m.get("score", "inconnu"),
                    lab.get("en_ligne", 0), lab.get("total", 0)))

    # ------------------------------------------------------ ingenierie inverse
    LIMITE_ECHANTILLON = 2 * 1024 * 1024

    def _reverse(self, payload):
        """Analyse d'un echantillon : empreinte, entropie, chaines, indicateurs."""
        import hashlib

        brut = None
        nom = str(payload.get("name") or "échantillon")
        b64 = payload.get("content_b64")
        chemin = str(payload.get("path") or "").strip()

        if b64:
            try:
                brut = base64.b64decode(b64, validate=False)
            except Exception:
                raise ValueError("contenu base64 invalide")
        elif chemin:
            cible = os.path.realpath(os.path.expanduser(chemin))
            racine = os.path.realpath(os.path.expanduser("~"))
            if not cible.startswith(racine):
                raise ValueError("chemin hors du dossier personnel refusé")
            if not os.path.isfile(cible):
                raise ValueError("fichier introuvable")
            if os.path.getsize(cible) > self.LIMITE_ECHANTILLON:
                raise ValueError("fichier trop volumineux (2 Mo max)")
            with open(cible, "rb") as fh:
                brut = fh.read()
            nom = os.path.basename(cible)
        else:
            raise ValueError("fournir content_b64 ou path")

        if not brut:
            raise ValueError("échantillon vide")
        tronque = len(brut) > self.LIMITE_ECHANTILLON
        donnees = brut[:self.LIMITE_ECHANTILLON]

        sha = hashlib.sha256(donnees).hexdigest()
        compte = {}
        for octet in donnees:
            compte[octet] = compte.get(octet, 0) + 1
        entropie = 0.0
        n = len(donnees)
        for c in compte.values():
            p = c / n
            entropie -= p * math.log2(p)

        texte = donnees.decode("latin-1", "replace")
        chaines = sorted({m for m in re.findall(r"[ -~]{5,}", texte)}, key=len, reverse=True)[:200]

        bas = donnees[:2]
        if bas == b"MZ":
            genre = "exécutable Windows (PE)"
        elif donnees[:2] == bytes([0x7F, 0x45]):
            genre = "binaire ELF"
        elif donnees[:4] in (b"%PDF",):
            genre = "document PDF"
        elif donnees[:4] == bytes([0x50, 0x4B, 0x03, 0x04]):
            genre = "archive ZIP/JAR/Office"
        elif donnees[:2] == bytes([0x1F, 0x8B]):
            genre = "archive gzip"
        else:
            imprimables = sum(1 for b in donnees[:4096] if 32 <= b < 127 or b in (9, 10, 13))
            genre = "texte" if n and imprimables / min(n, 4096) > .85 else "binaire"

        bas_texte = texte.lower()
        indicateurs = []

        def note(nom_ind, preuve, gravite="moyenne"):
            if len(indicateurs) < 40:
                indicateurs.append({"name": nom_ind, "evidence": preuve[:160], "severity": gravite})

        if bas == b"MZ":
            note("exécutable Windows", "en-tête MZ", "info")
        if "upx0" in bas_texte or "upx1" in bas_texte:
            note("emballage UPX", "section UPX détectée", "haute")
        if entropie > 7.5 and n > 4096:
            note("entropie très élevée", "%.2f bits/octet : données chiffrées ou compressées" % entropie, "haute")
        for api, motif in (
            ("injection mémoire", ("virtualalloc", "writeprocessmemory", "createremotethread")),
            ("persistance", ("regsetvalue", "createservice", "schtasks", "run\\", "startup")),
            ("chiffrement", ("cryptencrypt", "cryptgenkey", "aes_")),
            ("accès réseau", ("wsaStartup".lower(), "internetopen", "http://", "https://")),
            ("anti-analyse", ("isdebuggerpresent", "virtualbo", "vmware", "sandbox")),
            ("shell intégré", ("powershell", "cmd.exe /c", "/bin/sh", "bash -c")),
        ):
            for m2 in motif:
                if m2 in bas_texte:
                    note(api, "chaîne « %s »" % m2, "haute" if api in ("injection mémoire", "persistance") else "moyenne")
                    break
        liens = re.findall(r"""https?://[^\s"'<>]{6,}""", texte)
        if liens:
            note("URL intégrée", liens[0], "moyenne")
        if re.search(r"[A-Za-z0-9+/]{120,}={0,2}", texte):
            note("bloc base64 long", "chaîne encodée de plus de 120 caractères", "moyenne")
        if re.search(r"BEGIN (RSA |EC )?PRIVATE KEY", texte):
            note("clé privée en clair", "en-tête PEM de clé privée", "haute")

        return {
            "name": nom,
            "size": len(brut),
            "truncated": tronque,
            "sha256": sha,
            "entropy": round(entropie, 3),
            "kind": genre,
            "indicators": indicateurs,
            "strings": chaines[:60],
        }

    # ---------------------------------------------------------------- red team
    def _redteam(self):
        """Audit d'exposition de la machine : lecture seule, aucun paquet envoye."""
        controles = []

        def ajout(nom, statut, detail):
            controles.append({"name": nom, "status": statut, "detail": detail})

        bind = os.environ.get("SOC_BIND", "127.0.0.1")
        loopback = is_loopback_bind(bind) if "is_loopback_bind" in globals() else bind in ("127.0.0.1", "localhost", "::1")
        ajout("écoute du tableau de bord", "ok" if loopback else "fail",
              "bind %s%s" % (bind, "" if loopback else " : accessible depuis le réseau"))

        for var in ("SOC_READ_TOKEN", "SOC_INGEST_TOKEN"):
            present = bool(os.environ.get(var, "").strip())
            ajout("jeton %s" % var.lower(), "ok" if present else "warn",
                  "défini" if present else "vide : endpoints ouverts (toléré seulement en boucle locale)")

        lab_url = os.environ.get("SOC_LAB_URL", "http://127.0.0.1:8000")
        lab_hote = urllib.parse.urlparse(lab_url).hostname or ""
        ajout("orchestrateur", "ok" if lab_hote in ("127.0.0.1", "localhost", "::1") else "warn",
              "cible %s" % lab_url)

        couteux = [p for p in (55000, 9200) if _tcp_ouvert(p)]
        ajout("services Wazuh en local", "warn" if couteux else "ok",
              ("ports joignables depuis Windows : %s (attendu en WSL)" % ", ".join(map(str, couteux)))
              if couteux else "aucun service Wazuh directement joignable")

        vastes = _ecoutes_publiques()
        ajout("écoutes sur toutes les interfaces", "warn" if vastes else "ok",
              ("%d port(s) : %s" % (len(vastes), ", ".join(map(str, vastes[:10])))) if vastes else
              "aucun port en écoute sur 0.0.0.0 d'après netstat")

        ajout("transport du tableau de bord", "warn", "HTTP en clair : acceptable en boucle locale uniquement")

        deps = os.path.join(HERE, "requirements.txt")
        ajout("dépendances tierces", "ok" if not os.path.exists(deps) else "warn",
              "aucune (bibliothèque standard seule)" if not os.path.exists(deps) else "requirements.txt présent")

        ignore = os.path.join(HERE, ".gitignore")
        protege = False
        if os.path.exists(ignore):
            with open(ignore, "r", encoding="utf-8", errors="replace") as fh:
                protege = any(l.strip().lstrip("/") == ".env" for l in fh)
        ajout(".env protégé par .gitignore", "ok" if protege else "warn",
              "ignoré par git" if protege else ".gitignore absent ou sans .env")

        return {
            "checks": controles,
            "note": "Audit local, lecture seule : aucun paquet envoyé vers l'extérieur, aucun port non sollicité.",
        }

    def log_message(self, fmt, *args):
        if os.environ.get("SOC_QUIET", "1") == "1":
            if "/api/ingest" in (args[0] if args else ""):
                return
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


TOKEN_ENV = ("SOC_READ_TOKEN", "SOC_INGEST_TOKEN")
TRUTHY = {"1", "true", "oui", "yes", "on"}


def is_loopback_bind(host):
    """Vrai si l'interface d'ecoute ne sort pas de la machine."""
    value = (host or "").strip().lower()
    if value in ("", "localhost"):
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        # Un nom d'hote : on ne peut pas prouver qu'il est local, donc on
        # considere qu'il ne l'est pas. Le doute doit proteger, pas exposer.
        return False


def open_endpoint_tokens(bind, env=None):
    """Jetons absents qui rendraient l'API ouverte sur une interface reseau.

    Un bind non local avec un jeton vide, c'est une API sans authentification
    offerte au reseau. Le demarrage doit echouer bruyamment : un avertissement
    dans une banniere que personne ne lit ne protege de rien.
    """
    env = os.environ if env is None else env
    if is_loopback_bind(bind):
        return []
    if (env.get("SOC_ALLOW_OPEN_ENDPOINTS") or "").strip().lower() in TRUTHY:
        return []
    return [name for name in TOKEN_ENV if not (env.get(name) or "").strip()]


def main():
    load_dotenv()
    ap = argparse.ArgumentParser(description="Tableau de bord SOC")
    ap.add_argument("--port", type=int, default=int(os.environ.get("SOC_PORT", "8765")))
    ap.add_argument("--bind", default=os.environ.get("SOC_BIND", "127.0.0.1"))
    args = ap.parse_args()

    missing = open_endpoint_tokens(args.bind)
    if missing:
        sys.stderr.write(
            "Refus de demarrer : l'interface %s n'est pas locale et %s reste(nt) sans jeton.\n"
            % (args.bind, ", ".join(missing)))
        sys.stderr.write(
            "  Soit definir ces variables, soit assumer l'ouverture avec"
            " SOC_ALLOW_OPEN_ENDPOINTS=1.\n")
        return 2

    socstore.init()
    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    tok = os.environ.get("SOC_INGEST_TOKEN", "")
    read = os.environ.get("SOC_READ_TOKEN", "")
    print("=" * 66)
    print(" Tableau de bord SOC")
    print(" URL          : http://%s:%d" % (args.bind, args.port))
    print(" Base SQLite  : %s" % socstore.DB_PATH)
    print(" Ingestion    : %s" % ("jeton Bearer requis" if tok else "OUVERTE (definir SOC_INGEST_TOKEN)"))
    print(" Lecture      : %s" % ("jeton requis" if read
                                  else ("OUVERTE (interface locale uniquement)"
                                        if is_loopback_bind(args.bind) else "OUVERTE (assume)")))
    print(" Bilan        : %s" % ("LLM" if os.environ.get("SOC_LLM_API_KEY") else "moteur de regles (aucune cle LLM)"))
    print("=" * 66)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nArret.")
        httpd.server_close()


if __name__ == "__main__":
    # sys.exit : un refus de demarrage doit se voir dans le code de sortie,
    # sinon un script qui lance le tableau de bord le croit demarre.
    sys.exit(main())
