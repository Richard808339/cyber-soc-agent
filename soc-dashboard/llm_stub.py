#!/usr/bin/env python3
"""Faux fournisseur LLM compatible OpenAI — outil de verification.

Permet de verifier le chemin "bilan redige par un modele" sans cle d'API et sans
consommer de jetons : le serveur repond a POST /v1/chat/completions avec un texte
qui reprend les chiffres recus dans le prompt. Utilise par test_soc.py et pour la
demonstration locale.

    python llm_stub.py --port 8899
    # puis dans .env :
    #   SOC_LLM_API_KEY=stub
    #   SOC_LLM_BASE_URL=http://127.0.0.1:8899/v1
    #   SOC_LLM_MODEL=stub-model
"""

import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if not self.path.rstrip("/").endswith("/chat/completions"):
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self.send_response(400)
            self.end_headers()
            return

        prompt = "\n".join(m.get("content", "") for m in payload.get("messages", []))
        alertes = self._grab(prompt, r'"alerts_24h":\s*(\d+)')
        actifs = self._grab(prompt, r'"agents_active":\s*(\d+)')
        score = self._grab(prompt, r'"score":\s*(\d+)')
        critique = self._grab(prompt, r'"alerts_critique":\s*(\d+)')

        texte = (
            "## Situation en une phrase\n"
            "Bilan redige par un modele (serveur de verification) : %s alerte(s) sur 24 h, "
            "%s poste(s) actif(s), %s alerte(s) critique(s), score de posture %s/100. "
            "Les chiffres ci-dessus proviennent du snapshot transmis dans le prompt.\n\n"
            "## Ce qui ressort\n"
            "- Le modele a bien recu les metriques du collecteur, pas des valeurs inventees.\n"
            "- Sortie produite par llm_stub.py, sans appel reseau externe.\n\n"
            "## Priorites de reponse\n"
            "1. Traiter les %s alerte(s) critiques en priorite.\n\n"
            "## Angle mort connu\n"
            "Le manager Wazuh n'est pas expose sur Internet : seules les donnees poussees "
            "par le collecteur sont analysees." % (alertes, actifs, critique, score, critique)
        )

        body = json.dumps({
            "id": "chatcmpl-stub",
            "object": "chat.completion",
            "model": payload.get("model") or "stub-model",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": texte},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": len(prompt) // 4, "completion_tokens": len(texte) // 4,
                      "total_tokens": (len(prompt) + len(texte)) // 4},
        }).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _grab(text, pattern):
        m = re.search(pattern, text)
        return m.group(1) if m else "?"

    def log_message(self, fmt, *args):
        pass


def serve(port=0):
    """Demarre le serveur ; retourne (serveur, port). port=0 -> port libre."""
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    return httpd, httpd.server_address[1]


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Faux fournisseur LLM compatible OpenAI")
    ap.add_argument("--port", type=int, default=8899)
    args = ap.parse_args()
    httpd, port = serve(args.port)
    print("llm_stub a l'ecoute sur http://127.0.0.1:%d/v1" % port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()
