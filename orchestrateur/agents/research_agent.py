"""Research Agent : cherche reellement dans les documents locaux.

Perimetre : Documents/security (txt, md, log, conf, ps1, sh, py) + les rapports
generes pendant la session. Aucun acces reseau, aucune invention de source :
si rien ne correspond, il le dit.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path.home() / "Documents" / "security"
EXT = {".txt", ".md", ".log", ".conf", ".ps1", ".sh", ".py", ".json", ".csv"}
SKIP_DIRS = {"orchestrateur", "build", "__pycache__"}


def _files() -> list[Path]:
    if not ROOT.exists():
        return []
    out = []
    for p in ROOT.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in EXT:
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        out.append(p)
    return out


def run_research_task(payload: str) -> tuple[bool, str]:
    terms = [t for t in {w.strip(".,;:!?\"'()").lower() for w in payload.split()} if len(t) > 2]
    files = _files()
    print(f"  perimetre : {ROOT}  ({len(files)} fichier(s) texte)")
    print(f"  termes    : {terms or 'aucun terme exploitable'}")

    if not files:
        return False, f"aucun document exploitable sous {ROOT}"

    hits: dict[Path, list[str]] = {}
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            low = line.lower()
            if any(t in low for t in terms):
                hits.setdefault(f, []).append(f"{f.name}:{i}: {line.strip()[:110]}")

    if not hits:
        return False, f"aucune occurrence de {terms} dans {len(files)} document(s)"

    shown = 0
    for f, lines in sorted(hits.items()):
        print(f"  {f}  ({len(lines)} ligne(s))")
        for line in lines[:4]:
            print(f"    {line}")
            shown += 1
    return True, f"{sum(len(v) for v in hits.values())} occurrence(s) dans {len(hits)} document(s)"
