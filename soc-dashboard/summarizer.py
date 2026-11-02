"""Generation du bilan SOC.

Deux moteurs :
  - "llm"   : appel d'une API compatible OpenAI (DeepSeek, OpenAI, Ollama local...)
              si SOC_LLM_API_KEY est configure.
  - "regles": moteur deterministe hors ligne, qui redige un bilan en francais a
              partir des metriques. C'est le repli garanti : le tableau de bord
              reste utilisable sans cle d'API et sans reseau.

Aucune metrique n'est inventee : tout vient du snapshot ingere par le collecteur.
"""

import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone

LEVEL_LABELS = {
    "critique": "critique (>=12)",
    "eleve": "eleve (8-11)",
    "moyen": "moyen (4-7)",
    "faible": "faible (<=3)",
}


def severity_bucket(level):
    try:
        level = int(level)
    except (TypeError, ValueError):
        return "faible"
    if level >= 12:
        return "critique"
    if level >= 8:
        return "eleve"
    if level >= 4:
        return "moyen"
    return "faible"


def compute_metrics(snapshot):
    """Transforme un snapshot du collecteur en metriques exploitables."""
    alerts = snapshot.get("alerts") or {}
    agents = snapshot.get("agents") or []
    vulns = snapshot.get("vulnerabilities") or {}

    by_level = alerts.get("by_level") or {}
    crit = sum(int(v) for k, v in by_level.items() if int(k) >= 12)
    high = sum(int(v) for k, v in by_level.items() if 8 <= int(k) < 12)
    medium = sum(int(v) for k, v in by_level.items() if 4 <= int(k) < 8)

    active = [a for a in agents if (a.get("status") or "").lower() == "active"]
    down = [a for a in agents if (a.get("status") or "").lower() != "active"]
    crit_vulns = 0
    for sev, n in (vulns.get("by_severity") or {}).items():
        if str(sev).lower() in ("critical", "critique"):
            crit_vulns += int(n)

    return {
        "collected_at": snapshot.get("collected_at"),
        "agents_total": len(agents),
        "agents_active": len(active),
        "agents_down": [a.get("name") for a in down],
        "alerts_24h": int(alerts.get("total_24h") or 0),
        "alerts_critique": crit,
        "alerts_eleve": high,
        "alerts_moyen": medium,
        "top_rules": (alerts.get("top_rules") or [])[:5],
        "top_sources": (alerts.get("top_sources") or [])[:3],
        "per_agent": alerts.get("by_agent") or [],
        "vulns_total": int(vulns.get("total") or 0),
        "vulns_critique": crit_vulns,
        "manager_version": ((snapshot.get("manager") or {}).get("version") or "?"),
        "host": snapshot.get("host") or {},
        "score": posture_score(len(active), len(agents), crit, crit_vulns),
    }


def posture_score(active, total, crit_alerts, crit_vulns):
    """Score 0-100 : couverture des postes + bruit critique. Simple et explicite."""
    if total <= 0:
        return 0
    score = 100.0
    score -= (1 - active / total) * 40          # postes non couverts
    score -= min(crit_alerts, 10) * 2.0          # alertes critiques recentes
    score -= min(crit_vulns, 20) * 1.5           # vulnerabilites critiques
    return max(0, min(100, round(score)))


def _top_rules_sentence(metrics):
    rules = metrics.get("top_rules") or []
    if not rules:
        return "Aucune regle n'a domine le trafic d'alertes."
    parts = []
    for r in rules[:3]:
        label = r.get("key") or r.get("rule") or r.get("description") or "regle inconnue"
        parts.append("%s (%s alertes)" % (label, r.get("count")))
    return "Les regles les plus declenchees sont " + ", ".join(parts) + "."


def rules_summary(metrics):
    """Bilan deterministe, redige en francais, sans reseau ni modele."""
    a_tot = metrics["alerts_24h"]
    actifs = metrics["agents_active"]
    total = metrics["agents_total"]
    crit = metrics["alerts_critique"]
    high = metrics["alerts_eleve"]
    vulns = metrics["vulns_total"]
    cvuln = metrics["vulns_critique"]
    score = metrics["score"]

    if crit >= 3 or cvuln >= 5:
        posture = "degradee : plusieurs signaux critiques demandent une action aujourd'hui."
    elif crit >= 1 or high >= 5:
        posture = "sous tension : des signaux eleves sont a trier avant la fin de journee."
    elif a_tot == 0:
        posture = "saine, mais silencieuse : verifier que la collecte remonte bien."
    else:
        posture = "stable : le bruit d'alertes est majoritairement de faible gravite."

    lines = []
    lines.append("## Situation en une phrase")
    lines.append(
        "Sur les 24 dernieres heures, le SOC a enregistre %d alerte(s) pour %d poste(s) "
        "surveille(s) (%d actif(s)), dont %d critique(s) et %d eleve(s). "
        "La posture est %s Score de posture : %d/100."
        % (a_tot, total, actifs, crit, high, posture, score)
    )

    lines.append("")
    lines.append("## Ce qui ressort")
    lines.append("- " + _top_rules_sentence(metrics))
    if metrics["agents_down"]:
        lines.append("- Angle mort : poste(s) injoignable(s) - %s. Aucune alerte ne remontera "
                     "de ces machines tant qu'elles ne sont pas reconnectees."
                     % ", ".join(str(n) for n in metrics["agents_down"]))
    else:
        lines.append("- Couverture complete : tous les postes enregistres repondent.")
    if vulns:
        lines.append("- Exposition logicielle : %d vulnerabilite(s) connue(s) sur le perimetre%s."
                     % (vulns, ", dont %d critique(s)" % cvuln if cvuln else ""))
    if metrics.get("top_sources"):
        srcs = ", ".join("%s (%s)" % (s.get("key"), s.get("count")) for s in metrics["top_sources"])
        lines.append("- Sources les plus actives dans les alertes : %s." % srcs)

    lines.append("")
    lines.append("## Priorites de reponse")
    prio = []
    if crit:
        prio.append("Traiter en premier les %d alerte(s) critiques : ouvrir le playbook associe "
                    "dans le flux d'alertes, verifier si l'action a abouti." % crit)
    if cvuln:
        prio.append("Corriger les %d vulnerabilite(s) critiques (mise a jour ou desactivation "
                    "du service expose)." % cvuln)
    if metrics["agents_down"]:
        prio.append("Reconnecter les postes muets pour retrouver la visibilite.")
    if not prio:
        prio.append("Aucune action urgente : maintenir la surveillance et revoir les regles "
                    "les plus bruyantes pour reduire le bruit.")
    for i, p in enumerate(prio, 1):
        lines.append("%d. %s" % (i, p))

    lines.append("")
    lines.append("## Angle mort connu")
    lines.append(
        "Le manager Wazuh (%s) tourne en local et n'est pas expose sur Internet : "
        "aucune application en ligne ne peut l'interroger directement. Ce bilan est donc "
        "produit a partir du dernier snapshot pousse par le collecteur%s."
        % (metrics["manager_version"],
           " (%s)" % metrics["collected_at"] if metrics.get("collected_at") else "")
    )
    return "\n".join(lines)


def _llm_prompt(metrics):
    return (
        "Tu es analyste SOC. A partir des metriques JSON ci-dessous, redige en francais un "
        "bilan operationnel en markdown, avec ces sections : ## Situation en une phrase, "
        "## Ce qui ressort, ## Priorites de reponse, ## Angle mort connu. "
        "N'invente aucune donnee absente du JSON, cite les chiffres exacts, "
        "reste factuel et concis (250 mots max).\n\n"
        + json.dumps(metrics, ensure_ascii=False, default=str)[:6000]
    )


def llm_summary(metrics, timeout=45):
    """Appel d'une API compatible OpenAI. Leve une exception si indisponible."""
    key = os.environ.get("SOC_LLM_API_KEY", "").strip()
    if not key:
        raise RuntimeError("SOC_LLM_API_KEY absent")
    base = os.environ.get("SOC_LLM_BASE_URL", "https://api.deepseek.com/v1").rstrip("/")
    model = os.environ.get("SOC_LLM_MODEL", "deepseek-chat")

    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": "Tu rediges des bilans SOC factuels et actionnables."},
            {"role": "user", "content": _llm_prompt(metrics)},
        ],
        "temperature": 0.2,
        "max_tokens": 900,
    }).encode("utf-8")

    req = urllib.request.Request(
        base + "/chat/completions",
        data=body,
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + key},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    text = (data.get("choices") or [{}])[0].get("message", {}).get("content", "").strip()
    if not text:
        raise RuntimeError("reponse LLM vide")
    usage = data.get("usage") or {}
    return {
        "text": text,
        "engine": "llm",
        "model": data.get("model") or model,
        "tokens": usage.get("total_tokens"),
    }


def summarize(snapshot, prefer_llm=True):
    """Retourne le bilan + les metriques utilisees. Repli automatique sur les regles."""
    metrics = compute_metrics(snapshot)
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")

    if prefer_llm and os.environ.get("SOC_LLM_API_KEY", "").strip():
        try:
            out = llm_summary(metrics)
            out.update({"generated_at": generated, "metrics": metrics, "fallback": None})
            return out
        except Exception as exc:  # reseau, quota, cle invalide...
            fallback = rules_summary(metrics)
            return {
                "text": fallback,
                "engine": "regles",
                "model": "moteur interne",
                "generated_at": generated,
                "metrics": metrics,
                "fallback": "LLM indisponible : %s" % exc.__class__.__name__,
            }

    return {
        "text": rules_summary(metrics),
        "engine": "regles",
        "model": "moteur interne",
        "generated_at": generated,
        "metrics": metrics,
        "fallback": None if prefer_llm else "LLM desactive pour cette requete",
    }
