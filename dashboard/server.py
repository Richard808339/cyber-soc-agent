"""Serveur local du tableau de bord SOC (bibliotheque standard uniquement).

Routes :
    GET  /                 -> interface
    GET  /api/snapshot     -> dernier snapshot JSON
    POST /api/refresh      -> relance le collecteur puis renvoie le snapshot
    GET  /health           -> etat du service

Aucune connexion sortante : le serveur lit un fichier produit par l'agent.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
SNAP = ROOT / "data" / "snapshot.json"
LOCK = threading.Lock()
HOST = os.environ.get("DASH_HOST", "127.0.0.1")
PORT = int(os.environ.get("DASH_PORT", "8099"))


def _snapshot_text() -> str:
    if not SNAP.exists():
        import collector
        collector.main()
    return SNAP.read_text(encoding="utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "SOCDashboard/1.0"

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, text: str) -> None:
        self._send(code, text.encode("utf-8"), "application/json; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/index.html"):
            html = (WEB / "index.html").read_text(encoding="utf-8")
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
        elif self.path == "/api/snapshot":
            self._json(200, _snapshot_text())
        elif self.path == "/health":
            self._json(200, json.dumps({"ok": True}))
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/api/refresh":
            if not LOCK.acquire(blocking=False):
                self._json(409, json.dumps({"ok": False, "error": "collecte deja en cours"}))
                return
            try:
                import collector
                collector.main()
                self._json(200, _snapshot_text())
            except Exception as exc:
                self._json(500, json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}))
            finally:
                LOCK.release()
        else:
            self._send(404, b"not found", "text/plain")

    def log_message(self, fmt: str, *args) -> None:
        if os.environ.get("DASH_VERBOSE"):
            sys.stderr.write("[dash] " + fmt % args + "\n")


def main() -> int:
    if not SNAP.exists():
        try:
            import collector
            collector.main()
        except Exception as exc:
            print(f"collecte initiale impossible : {exc}", file=sys.stderr)
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Tableau de bord SOC : http://{HOST}:{PORT}/")
    print(f"snapshot           : {SNAP}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\narret")
    return 0


if __name__ == "__main__":
    sys.exit(main())
