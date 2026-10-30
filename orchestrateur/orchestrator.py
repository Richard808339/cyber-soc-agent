"""Orchestrateur multi-agents - version reelle.

Difference avec la version d'origine : chaque route appelle vraiment son agent et
rapporte ce qu'il a obtenu. Aucune ligne de succes n'est affichee sans preuve.

Usage :
    python orchestrator.py cyber "statut des agents"
    python orchestrator.py builder "generer un script de sauvegarde"
    python orchestrator.py research "wazuh agent"
"""
from __future__ import annotations

import sys

try:  # garde l'affichage lisible quel que soit le code page Windows
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from agents.cyber_agent import run_cyber_task
from agents.builder_agent import run_builder_task
from agents.research_agent import run_research_task


ROUTES = {
    "cyber": ("Cyber Agent (Wazuh, SOC, agents)", run_cyber_task),
    "builder": ("Builder Agent (scripts, code, automatisation)", run_builder_task),
    "research": ("Research Agent (documents locaux, veille)", run_research_task),
}


def route_to_agent(domain: str, payload: str) -> int:
    """Route la mission vers l'agent specialise et renvoie un code de sortie."""
    domain = (domain or "").strip().lower()
    print(f"\n[ORCHESTRATOR] domaine={domain.upper()}  payload={payload!r}\n")

    if domain not in ROUTES:
        print(f"[ORCHESTRATOR] domaine inconnu : {domain!r}")
        print(f"               domaines valides : {', '.join(sorted(ROUTES))}")
        return 2

    label, handler = ROUTES[domain]
    print(f"[ROUTING] -> {label}")
    try:
        ok, message = handler(payload)
    except Exception as exc:  # un agent qui plante ne doit pas masquer l'erreur
        print(f"[ERREUR] {label} : {type(exc).__name__}: {exc}")
        return 1

    prefix = "OK   " if ok else "ECHEC"
    print(f"[{prefix}] {label} : {message}")
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if len(argv) > 2:
        return route_to_agent(argv[1], " ".join(argv[2:]))

    print("=" * 62)
    print(" HERMES ORCHESTRATOR")
    print(" python orchestrator.py <domaine> \"<description>\"")
    print(" domaines : cyber, builder, research")
    print("=" * 62)
    return route_to_agent("cyber", "etat des agents du SOC")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
