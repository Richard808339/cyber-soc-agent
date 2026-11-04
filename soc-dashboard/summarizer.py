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
    stack = snapshot.get("stack") or {}

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
        "stack_containers": len(stack.get("containers") or []),
        "stack_down": [c.get("name") for c in (stack.get("containers") or [])
                       if not str(c.get("status") or "").lower().startswith("up")],
        "indexer_health": stack.get("indexer_health"),
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


def findings(snapshot):
    """Diagnostic automatique du SOC : ce qui empeche de voir ou de detecter.

    Chaque constat porte une preuve et des actions concretes. Aucune deduction
    n'est faite sans donnee correspondante dans le snapshot.
    """
    out = []
    alerts = snapshot.get("alerts") or {}
    agents = snapshot.get("agents") or []
    stack = snapshot.get("stack") or {}
    errors = snapshot.get("errors") or []
    total = int(alerts.get("total_24h") or 0)
    down = [a for a in agents if (a.get("status") or "").lower() != "active"]

    if any(str(e).startswith("agents:") for e in errors):
        out.append({
            "level": "critique",
            "title": "API Wazuh muette : aucun poste lisible",
            "detail": "La collecte n'a pas pu lire la liste des agents. Soit l'API du "
                      "manager est arretee, soit le manager ne repond pas : le tableau de "
                      "bord ne peut plus decrire le parc.",
            "evidence": [e for e in errors if str(e).startswith("agents:")][0][:160],
            "actions": [
                "docker logs --tail 30 single-node-wazuh.manager-1 | grep -i apid",
                "docker restart single-node-wazuh.manager-1 si l'API ne demarre pas",
                "curl -sk -o /dev/null -w '%{http_code}' -u <user>:<pass> https://localhost:55000/security/user/authenticate",
            ],
        })
    elif not agents:
        out.append({
            "level": "critique",
            "title": "Aucun poste enregistre",
            "detail": "Le manager repond mais ne connait aucun agent : enrolement perdu "
                      "ou cluster vide.",
            "evidence": "GET /agents -> liste vide",
            "actions": ["Verifier l'enrolement des agents (port 1515)",
                        "docker logs --since 1h single-node-wazuh.manager-1 | grep -i enroll"],
        })

    if total == 0:
        out.append({
            "level": "eleve",
            "title": "Aucun signal sur 24 h",
            "detail": "Zero alerte indexee sur 24 heures. Un SOC silencieux n'est pas un "
                      "SOC sain : c'est le plus souvent un agent muet ou un indexeur qui "
                      "n'ecrit plus.",
            "evidence": "agregation timestamp >= now-24h sur wazuh-alerts-* : 0 document",
            "actions": ["docker ps (les trois conteneurs doivent etre Up)",
                        "Verifier le dernier keepalive des agents dans /agents",
                        "Verifier _cluster/health de l'indexeur"],
        })

    if down:
        out.append({
            "level": "eleve",
            "title": "Poste(s) injoignable(s) : %d" % len(down),
            "detail": "Ces postes ne remontent plus rien : angle mort de la surveillance.",
            "evidence": ", ".join("%s (%s)" % (a.get("name"), a.get("status")) for a in down),
            "actions": ["Get-Service WazuhSvc sur le poste concerne",
                        "Test-NetConnection -ComputerName <manager> -Port 1514",
                        "Restart-Service WazuhSvc"],
        })

    health = stack.get("indexer_health")
    if health and str(health).lower() != "green":
        out.append({
            "level": "eleve" if str(health).lower() == "red" else "moyen",
            "title": "Indexeur en etat %s" % health,
            "detail": "L'indexation n'est pas nominale : les alertes peuvent arriver en "
                      "retard ou manquer.",
            "evidence": "_cluster/health -> status=%s" % health,
            "actions": ["curl -sk -u admin:<pass> https://localhost:9200/_cluster/health?pretty",
                        "Verifier l'espace disque : df -h dans la distro WSL"],
        })

    for c in stack.get("containers") or []:
        status = (c.get("status") or "").lower()
        if not status.startswith("up"):
            out.append({
                "level": "critique",
                "title": "Conteneur arrete : %s" % c.get("name"),
                "detail": "Un composant de la pile Wazuh n'est pas en marche.",
                "evidence": "%s -> %s" % (c.get("name"), c.get("status")),
                "actions": ["docker start %s" % c.get("name"),
                            "docker logs --tail 50 %s" % c.get("name")],
            })

    rejects = stack.get("enrollment_rejected_30m")
    if rejects and rejects > 5:
        out.append({
            "level": "moyen",
            "title": "Refus d'enrolement : %d en 30 min" % rejects,
            "detail": "Des agents tentent de s'enregistrer et sont refuses : mot de passe "
                      "d'agent different, ou tentative d'intrusion sur le port 1515.",
            "evidence": "docker logs --since 30m <manager> | grep -c 'rejecting enrollment'",
            "actions": ["Verifier le authd.pass cote agent",
                        "Si la source est inconnue, filtrer le port 1515"],
        })

    if not stack.get("available"):
        out.append({
            "level": "moyen",
            "title": "Pile Wazuh non inspectable depuis ce poste",
            "detail": "Le collecteur n'a pas pu lire l'etat des conteneurs : diagnostic "
                      "limite aux donnees API/indexeur.",
            "evidence": str(stack.get("error") or "docker ps indisponible")[:160],
            "actions": ["Verifier que wsl.exe -d <distro> docker ps repond",
                        "Ajuster WAZUH_WSL_DISTRO / WAZUH_MANAGER_CONTAINER dans .env"],
        })

    reseau = snapshot.get("network") or {}
    nouveaux = reseau.get("nouveaux") or []
    if nouveaux:
        niveau = (os.environ.get("SOC_NEW_DEVICE_LEVEL") or "eleve").strip().lower()
        if niveau not in ("critique", "eleve", "moyen", "faible"):
            niveau = "eleve"
        out.append({
            "level": niveau,
            "title": "Nouvel appareil sur le reseau local : %d" % len(nouveaux),
            "detail": "Appareil(s) jamais vu(s) dans l'inventaire ARP. Un equipement "
                      "inconnu sur le LAN merite d'etre identifie : materiel legitime "
                      "ou intrusion.",
            "evidence": ", ".join(
                "%s (%s%s)" % (n.get("ip"), n.get("mac"),
                               (" — " + n["constructeur"]) if n.get("constructeur") else "")
                for n in nouveaux[:5]),
            "actions": ["Identifier les adresses MAC : constructeur via le prefixe OUI",
                        "Verifier /ip/dhcp-server/lease sur le routeur MikroTik",
                        "Si inconnu : l'isoler du LAN puis enqueter"],
        })

    return out


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
    if metrics.get("stack_containers"):
        etat = "tous demarres" if not metrics.get("stack_down") else \
            "arret(s) : " + ", ".join(metrics["stack_down"])
        lines.append("- Pile Wazuh : %d conteneur(s), %s, indexeur %s."
                     % (metrics["stack_containers"], etat, metrics.get("indexer_health") or "inconnu"))

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
