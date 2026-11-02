"""Genere preview.html : la meme interface, avec le snapshot injecte.

Sert a afficher le tableau de bord sans serveur (apercu en chat, envoi par mail,
ou consultation hors ligne). Le fichier produit est autonome.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "web" / "index.html"
SNAP = ROOT / "data" / "snapshot.json"
OUT = ROOT / "preview.html"

MARK = "<script>\nconst EMBEDDED"


def main() -> int:
    html = SRC.read_text(encoding="utf-8")
    snap = json.loads(SNAP.read_text(encoding="utf-8"))
    inject = ("<script>window.__SNAPSHOT__ = "
              + json.dumps(snap, ensure_ascii=False)
              + ";</script>\n<script>const EMBEDDED")
    if MARK not in html:
        raise SystemExit("marqueur introuvable dans index.html")
    OUT.write_text(html.replace(MARK, inject, 1), encoding="utf-8")
    print(f"preview ecrit : {OUT} ({OUT.stat().st_size} octets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
