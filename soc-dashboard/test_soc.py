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
