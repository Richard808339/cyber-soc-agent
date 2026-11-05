#!/usr/bin/env python3
"""Blocage d'adresse IP dans le pare-feu Windows, sous approbation humaine.

    python block_ip.py block 198.51.100.23 --reason "brute force SSH"
    python block_ip.py unblock 198.51.100.23
    python block_ip.py list

Le point important : rien n'est execute sans un accord humain enregistre. La commande
passe par le broker (broker.py) qui la classe « critique », envoie une demande, attend
la decision et n'execute qu'apres approbation. Un webhook qui executerait directement
`New-NetFirewallRule` serait un chemin d'execution distant protege par un simple jeton.

Codes de sortie :
    0  action effectuee (ou simulation reussie)
    1  refusee, expiree ou non approuvee
    2  entree invalide (adresse refusee)
    3  privileges manquants
    4  echec de l'execution
"""

import argparse
import ipaddress
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import broker  # noqa: E402

SCRIPT = os.path.join(HERE, "block_ip.ps1")

# Plages interdites par defaut : bloquer sa propre passerelle coupe le poste du reseau.
PRIVEES = (
    ("10.0.0.0/8", "plage privee 10.0.0.0/8"),
    ("172.16.0.0/12", "plage privee 172.16.0.0/12"),
    ("192.168.0.0/16", "plage privee 192.168.0.0/16"),
    ("169.254.0.0/16", "plage lien-local / APIPA"),
    ("127.0.0.0/8", "boucle locale"),
    ("0.0.0.0/8", "adresse non specifiee"),
    ("224.0.0.0/4", "multicast"),
    ("240.0.0.0/4", "plage reservee"),
)


def valider_ip(texte, allow_private=False):
    """Retourne (adresse_normalisee, motif_de_refus). Une seule des deux est non nulle."""
    brut = (texte or "").strip()
    if not brut:
        return None, "adresse vide"
    if "/" in brut:
        reseau, _, bits = brut.partition("/")
        if bits not in ("32", "128"):
            return None, "seule une adresse seule ou un /32 est acceptee"
        brut = reseau
    try:
        adresse = ipaddress.ip_address(brut)
    except ValueError:
        return None, "adresse IP invalide"
    if adresse.version == 6 and adresse.ipv4_mapped:
        adresse = adresse.ipv4_mapped

    if not allow_private:
        for plage, motif in PRIVEES:
            if adresse in ipaddress.ip_network(plage):
                return None, "adresse locale ou protegee : %s" % motif
        if adresse.is_loopback:
            return None, "adresse locale ou protegee : boucle locale"
        if adresse.is_link_local:
            return None, "adresse locale ou protegee : lien-local"
        if adresse.is_multicast or adresse.is_reserved or adresse.is_unspecified:
            return None, "adresse locale ou protegee : reservee"
    return str(adresse), None


def nettoyer_raison(texte):
    """Le motif finit dans une ligne de commande : on retire ce qui pourrait l'ouvrir.

    Le broker refuse de toute facon les metacaracteres a l'execution ; les laisser
    ici produirait une demande d'approbation impossible a executer.
    """
    sales = ";&|<>`$" + chr(10) + chr(13) + chr(9)
    propres = "".join(" " if c in sales else c for c in (texte or ""))
    propres = " ".join(propres.split())[:120]
    return propres or "IOC signale par le SOC"


def nom_regle(ip, sens="in"):
    return "SOC-Block-%s-%s" % (str(ip).replace(":", "-").replace(".", "-"), sens)


def commande(ip, action="Block", direction="Inbound", raison="IOC signale par le SOC",
             simulation=False, allow_private=False):
    """Commande exacte qui sera approuvee puis executee (argv, sans shell)."""
    argv = [
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", SCRIPT,
        "-IpAddress", str(ip),
        "-Action", action,
        "-Direction", direction,
        "-Reason", nettoyer_raison(raison),
    ]
    if allow_private:
        argv.append("-AllowPrivate")
    if simulation:
        argv.append("-WhatIf")
    return argv


def masquer(argv):
    """Forme lisible enregistree dans la demande d'approbation."""
    return " ".join('"%s"' % a if " " in a else a for a in argv)


def demander(argv, motif_risque="regle de pare-feu Windows", details="", ttl=None):
    """Cree la demande d'approbation. Le risque est force : jamais « inoffensif »."""
    code, risque, motif = broker.new_request(
        masquer(argv),
        agent="soc-block-ip",
        details=details or "blocage d'adresse IP demande par l'analyste",
        risk="critique",
        ttl=ttl,
    )
    try:
        broker.notify_request(code, masquer(argv), "soc-block-ip",
                              details or "blocage d'adresse IP", risque)
    except Exception:
        pass  # l'absence de notification ne doit pas annuler la demande
    return {"id": code, "risk": risque, "motif": motif}


def executer(code):
    ok, sortie = broker.execute(code)
    charge = None
    for ligne in reversed((sortie or "").splitlines()):
        ligne = ligne.strip()
        if ligne.startswith("{"):
            try:
                charge = json.loads(ligne)
                break
            except ValueError:
                continue
    return ok, sortie, charge


def principal(argv=None):
    p = argparse.ArgumentParser(description="Blocage d'IP pare-feu Windows sous approbation.")
    p.add_argument("action", choices=["block", "unblock", "list"])
    p.add_argument("ip", nargs="?")
    p.add_argument("--reason", default="IOC signale par le SOC")
    p.add_argument("--direction", default="Inbound", choices=["Inbound", "Outbound", "Both"])
    p.add_argument("--allow-private", action="store_true",
                   help="autorise une adresse privee (a n'utiliser qu'en connaissance de cause)")
    p.add_argument("--whatif", action="store_true", help="simulation : ne touche pas au pare-feu")
    p.add_argument("--json", action="store_true", help="sortie machine")
    p.add_argument("--no-wait", action="store_true", help="cree la demande et rend la main")
    p.add_argument("--timeout", type=int, default=None)
    args = p.parse_args(argv)

    if args.action == "list":
        lignes = broker.list_requests(limit=20)
        if args.json:
            print(json.dumps([dict(l) for l in lignes], ensure_ascii=False))
        else:
            for l in lignes:
                print("%s  %-10s %s" % (l["id"], l["status"], l["action"][:90]))
        return 0

    if not args.ip:
        print("adresse IP manquante", file=sys.stderr)
        return 2

    ip, motif = valider_ip(args.ip, allow_private=args.allow_private)
    if not ip:
        sortie = {"statut": "refuse", "motif": motif, "ip": args.ip}
        print(json.dumps(sortie, ensure_ascii=False) if args.json else "refusé : " + motif)
        return 2

    action = "Block" if args.action == "block" else "Unblock"
    cmd = commande(ip, action=action, direction=args.direction, raison=args.reason,
                   simulation=args.whatif, allow_private=args.allow_private)
    demande = demander(cmd, details="%s %s (%s)" % (action.lower(), ip, args.reason))
    code = demande["id"]

    if args.json:
        print(json.dumps({"statut": "en_attente", "id": code, "action": masquer(cmd)}, ensure_ascii=False))
    else:
        print("demande %s créée (risque critique)" % code)
        print("  commande : %s" % masquer(cmd))
        print("  approuver : python broker.py approve %s" % code)
        print("  refuser   : python broker.py deny %s" % code)

    if args.no_wait:
        return 0

    decision = broker.wait_for_decision(code, args.timeout)
    if decision != "approved":
        sortie = {"statut": "non_approuvee", "decision": decision, "id": code}
        print(json.dumps(sortie, ensure_ascii=False) if args.json else "non approuvée (%s)" % decision)
        return 1

    ok, brut, charge = executer(code)
    if args.json:
        print(json.dumps({"statut": "execute" if ok else "echec", "id": code,
                          "resultat": charge, "sortie": brut}, ensure_ascii=False))
    else:
        print("exécution : %s" % ("ok" if ok else "échec"))
        if charge:
            for r in charge.get("resultats", []):
                print("  %-28s %s" % (r.get("regle"), r.get("statut")))
            if charge.get("motif"):
                print("  motif : %s" % charge["motif"])
        elif brut:
            print("  " + brut.strip()[:400])

    if not ok:
        return 4
    if charge and charge.get("statut") == "privileges":
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(principal())
