#!/usr/bin/env python3
"""Bilan quotidien du SOC, pousse sur Telegram.

Independant du serveur web : le script interroge Wazuh lui-meme (meme collecte
que le collecteur), redige le bilan, et l'envoie. Le tableau de bord peut etre
arrete, le bilan part quand meme.

Usage :
    python daily_digest.py            # envoi Telegram
    python daily_digest.py --dry-run  # affiche le message sans l'envoyer
    python daily_digest.py --mock     # verifie le rendu sur des donnees simulees
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import collector  # noqa: E402
import notifier  # noqa: E402
import summarizer  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

MOCK = {
    "collected_at": "2026-11-02T08:00:00+00:00",
    "agents": [{"name": "wazuh.manager", "status": "active"},
               {"name": "zbook-hp", "status": "active"}],
    "alerts": {"total_24h": 958, "by_level": {"3": 900, "5": 56, "12": 2}},
    "stack": {"available": True, "indexer_health": "green",
              "enrollment_rejected_30m": 0,
              "containers": [{"name": "single-node-wazuh.manager-1", "status": "Up 8 hours"},
                             {"name": "single-node-wazuh.indexer-1", "status": "Up 8 hours"},
                             {"name": "single-node-wazuh.dashboard-1", "status": "Up 8 hours"}]},
    "vulnerabilities": {"total": 6, "by_severity": {"Critical": 1, "High": 2}},
    "errors": [],
}


def construire(snapshot):
    """Message pret a envoyer : chiffres, phrase de bilan, constats ouverts."""
    resume = summarizer.summarize(snapshot)
    url = (os.environ.get("SOC_PUBLIC_URL") or "").strip() or None
    texte = notifier.build_digest_message(snapshot, resume.get("text"), url)

    constats = summarizer.findings(snapshot)
    if constats:
        texte += "\n\n<b>Points ouverts</b>"
        for f in constats[:5]:
            texte += "\n%s %s" % (notifier.LEVEL_TAG.get(f.get("level"), "[INFO]"),
                                  notifier._e(f.get("title")))
    else:
        texte += "\n\nAucun point ouvert : postes actifs, pile demarree, indexeur OK."
    return texte, resume


def main():
    ap = argparse.ArgumentParser(description="Bilan quotidien SOC -> Telegram")
    ap.add_argument("--dry-run", action="store_true", help="affiche sans envoyer")
    ap.add_argument("--mock", action="store_true", help="donnees simulees")
    args = ap.parse_args()

    notifier.load_dotenv()
    snapshot = MOCK if args.mock else collector.build_snapshot()

    texte, resume = construire(snapshot)
    print("[bilan] moteur=%s | %d caracteres" % (resume.get("engine"), len(texte)))
    if args.dry_run or args.mock:
        print(texte)
        if args.mock:
            return 0
    if args.dry_run:
        return 0

    res = notifier.send(texte)
    print("[bilan] envoye (message %s)" % res.get("message_id"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
