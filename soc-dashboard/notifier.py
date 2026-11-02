#!/usr/bin/env python3
"""Notifications Telegram du tableau de bord SOC.

Le tableau de bord pousse vers le bot Telegram quand quelque chose merite une
alerte humaine : constat critique, poste muet, pile en panne. Pas de dependance :
API HTTP Bot de Telegram, urllib seulement.

Configuration (.env) :
    SOC_TELEGRAM_TOKEN=123456:AA...        (jeton du bot)
    SOC_TELEGRAM_CHAT_ID=123456789         (destinataire)
    SOC_NOTIFY=1                           (0 = notifications desactivees)
    SOC_NOTIFY_COOLDOWN=900                (secondes entre deux messages identiques)
    SOC_PUBLIC_URL=http://...              (lien affiche dans le message, optionnel)

Usage :
    python notifier.py --test      # envoie un message de verification
    python notifier.py --digest    # envoie le bilan courant
    python notifier.py --dry-run   # affiche le message sans l'envoyer
"""

import argparse
import hashlib
import html
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import socstore  # noqa: E402
import summarizer  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

API = "https://api.telegram.org/bot%s/sendMessage"
LEVEL_ICON = {"critique": "🔴", "eleve": "🟠", "moyen": "🟡", "faible": "⚪"}


def load_dotenv(path=None):
    path = path or os.path.join(HERE, ".env")
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8-sig") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def credentials():
    token = (os.environ.get("SOC_TELEGRAM_TOKEN") or "").strip()
    chat = (os.environ.get("SOC_TELEGRAM_CHAT_ID") or "").strip()
    if not token or not chat:
        raise RuntimeError("SOC_TELEGRAM_TOKEN / SOC_TELEGRAM_CHAT_ID absents du .env")
    return token, chat


def send(text, token=None, chat=None, timeout=20):
    """Envoie un message Telegram. Retourne la reponse API (ok, message_id)."""
    token, chat = (token, chat) if token and chat else credentials()
    body = urllib.parse.urlencode({
        "chat_id": chat,
        "text": text[:4000],
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    }).encode("utf-8")
    req = urllib.request.Request(API % token, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:200]
        raise RuntimeError("Telegram HTTP %s : %s" % (exc.code, detail))
    if not data.get("ok"):
        raise RuntimeError("Telegram : %s" % data.get("description"))
    result = data.get("result") or {}
    return {"ok": True, "message_id": result.get("message_id"),
            "chat": (result.get("chat") or {}).get("username") or result.get("chat", {}).get("id")}


def _e(value):
    return html.escape(str(value if value is not None else ""))


def build_alert_message(snapshot, findings, dashboard_url=None):
    """Message d'alerte : ce qui a change et qui demande une action."""
    m = summarizer.compute_metrics(snapshot)
    crit = [f for f in findings if f.get("level") == "critique"]
    high = [f for f in findings if f.get("level") == "eleve"]
    others = [f for f in findings if f.get("level") not in ("critique", "eleve")]

    head = "🔴 <b>SOC — %d constat(s) critique(s)</b>" % len(crit) if crit else \
           "🟠 <b>SOC — %d constat(s) élevé(s)</b>" % len(high) if high else \
           "🟡 <b>SOC — %d point(s) à surveiller</b>" % len(others) if others else \
           "🟢 <b>SOC — rien à signaler</b>"

    lignes = [head, ""]
    lignes.append("%d/%d poste(s) actif(s) · %d alerte(s)/24 h · score %d/100"
                  % (m["agents_active"], m["agents_total"], m["alerts_24h"], m["score"]))
    stack = snapshot.get("stack") or {}
    if stack.get("containers"):
        etat = "arret(s) : " + ", ".join(m["stack_down"]) if m.get("stack_down") else "tous démarrés"
        lignes.append("Pile : %d conteneur(s), %s, indexeur %s"
                      % (len(stack["containers"]), etat, stack.get("indexer_health") or "?"))

    for bloc, titre in ((crit, "À traiter maintenant"), (high, "À vérifier"), (others, "À surveiller")):
        if not bloc:
            continue
        lignes.append("")
        lignes.append("<b>%s</b>" % titre)
        for f in bloc[:4]:
            lignes.append("%s %s" % (LEVEL_ICON.get(f.get("level"), "•"), _e(f.get("title"))))
            premiere = (f.get("actions") or [None])[0]
            if premiere:
                lignes.append("   <code>%s</code>" % _e(premiere)[:180])

    if not (crit or high or others):
        lignes.append("")
        lignes.append("Aucun constat bloquant : postes actifs, pile démarrée, indexeur OK.")

    lignes.append("")
    if dashboard_url:
        lignes.append('<a href="%s">Ouvrir le tableau de bord</a>' % _e(dashboard_url))
    lignes.append("<i>%s UTC</i>" % datetime.now(timezone.utc).strftime("%d/%m %H:%M"))
    return "\n".join(lignes)


def build_digest_message(snapshot, summary_text, dashboard_url=None):
    """Message de bilan : version courte du bilan redige."""
    m = summarizer.compute_metrics(snapshot)
    lignes = ["📊 <b>Bilan SOC</b>", ""]
    lignes.append("%d/%d poste(s) actif(s) · %d alerte(s)/24 h · %d critique(s) · score %d/100"
                  % (m["agents_active"], m["agents_total"], m["alerts_24h"],
                     m["alerts_critique"], m["score"]))
    lignes.append("")
    for line in (summary_text or "").splitlines():
        clean = line.strip()
        if clean.startswith("## ") or not clean:
            continue
        clean = clean.lstrip("-").strip()
        if clean.startswith("Sur les 24") or clean.startswith("Sur les"):
            lignes.append(_e(clean)[:420])
            break
    if dashboard_url:
        lignes.append("")
        lignes.append('<a href="%s">Tableau de bord</a>' % _e(dashboard_url))
    return "\n".join(lignes)


def should_alert(findings, cooldown_seconds=None):
    """Faut-il notifier ? Seuls les constats critiques/eleves declenchent une alerte."""
    cooldown = int(cooldown_seconds if cooldown_seconds is not None
                   else (os.environ.get("SOC_NOTIFY_COOLDOWN") or 900))
    graves = [f for f in findings if f.get("level") in ("critique", "eleve")]
    if not graves:
        return False, None
    cle = hashlib.sha1("|".join(sorted(f.get("title") or "" for f in graves)).encode("utf-8")).hexdigest()[:16]
    if socstore.recently_notified(cle, cooldown):
        return False, cle
    return True, cle


def maybe_notify(snapshot, findings, dashboard_url=None):
    """Point d'entree appele par le tableau de bord a chaque collecte.

    Ne leve jamais : une panne Telegram ne doit pas casser l'ingestion.
    """
    if os.environ.get("SOC_NOTIFY", "1") not in ("1", "true", "True"):
        return {"sent": False, "reason": "notifications desactivees"}
    try:
        credentials()
    except RuntimeError as exc:
        return {"sent": False, "reason": str(exc)}

    envoyer, cle = should_alert(findings)
    if not envoyer:
        return {"sent": False, "reason": "rien de grave ou deja notifie"}

    try:
        message = build_alert_message(snapshot, findings, dashboard_url)
        res = send(message)
        socstore.mark_notified(cle)
        return {"sent": True, "cle": cle, **res}
    except Exception as exc:
        return {"sent": False, "reason": "%s: %s" % (exc.__class__.__name__, str(exc)[:160])}


def main():
    ap = argparse.ArgumentParser(description="Notifications Telegram du SOC")
    ap.add_argument("--test", action="store_true", help="envoie un message de verification")
    ap.add_argument("--digest", action="store_true", help="envoie le bilan courant")
    ap.add_argument("--dry-run", action="store_true", help="affiche sans envoyer")
    args = ap.parse_args()

    load_dotenv()
    socstore.init()
    snap = socstore.latest_snapshot()
    findings = summarizer.findings(snap) if snap else []
    url = os.environ.get("SOC_PUBLIC_URL") or None

    if args.test:
        texte = ("✅ <b>Test de connexion SOC</b>\n\n"
                 "Le tableau de bord est relié à ce bot.\n"
                 "Seuil d'alerte : constats critiques ou élevés.\n"
                 "<i>%s UTC</i>" % datetime.now(timezone.utc).strftime("%d/%m %H:%M"))
    elif args.digest:
        if not snap:
            raise SystemExit("Aucun snapshot : lancez d'abord le collecteur.")
        summary = summarizer.summarize(snap, prefer_llm=bool(os.environ.get("SOC_LLM_API_KEY")))
        texte = build_digest_message(snap, summary["text"], url)
    else:
        if not snap:
            raise SystemExit("Aucun snapshot : lancez d'abord le collecteur.")
        texte = build_alert_message(snap, findings, url)

    if args.dry_run:
        print(texte)
        return
    print(json.dumps(send(texte), ensure_ascii=False))


if __name__ == "__main__":
    main()
