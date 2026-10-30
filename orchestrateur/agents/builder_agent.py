"""Builder Agent : ecrit reellement un fichier, sans pretendre avoir 'genere' du code.

Le payload sert de description : l'agent produit un squelette de script executable
dans build/, avec en-tete, arguments et point d'entree. Il renvoie le chemin reel.
"""
from __future__ import annotations

import datetime as _dt
import re
from pathlib import Path

BUILD_DIR = Path(__file__).resolve().parent.parent / "build"


def _slug(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "_", text.lower()).strip("_")
    return (s or "script")[:40]


def run_builder_task(payload: str) -> tuple[bool, str]:
    BUILD_DIR.mkdir(exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    name = f"{_slug(payload)}_{stamp}.py"
    target = BUILD_DIR / name

    code = f'''#!/usr/bin/env python3
"""Squelette genere par le Builder Agent.

Demande : {payload}
Cree le : {_dt.datetime.now().isoformat(timespec="seconds")}

TODO : implementer la logique, puis supprimer cette ligne.
"""
from __future__ import annotations

import argparse
import sys


def run(**kwargs) -> int:
    """Point d'entree metier."""
    print("a implementer :", kwargs)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description={payload!r})
    parser.add_argument("--dry-run", action="store_true", help="simulation sans effet")
    args = parser.parse_args(argv)
    if args.dry_run:
        print("[dry-run] aucune action")
        return 0
    return run(dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
'''
    target.write_text(code, encoding="utf-8")
    size = target.stat().st_size
    print(f"  fichier ecrit : {target}  ({size} octets)")
    print("  contenu : squelette executable, non teste — a completer")
    return True, f"squelette cree dans {target} ({size} octets, a implementer)"
