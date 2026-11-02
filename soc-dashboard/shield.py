#!/usr/bin/env python3
"""Garde-fou en cours de processus : interception reelle des commandes.

Le broker seul ne protege que le code qui l'appelle. `shield` ferme cette
porte autrement : il remplace subprocess et os.system dans le processus courant,
classe chaque commande, et lève PermissionError si elle est sensible et non
approuvee. Un script maison qui oublie le broker est donc arrete quand meme.

Mise en place, en tete du script a proteger :

    import shield
    shield.install(agent="mon-agent")

Cas legitime : une action approuvee ailleurs. Le demandeur exporte l'identifiant
de la demande validee, et le garde-fou la consomme une seule fois :

    SOC_APPROVAL_ID=796b75f0 python mon_script.py

Limite assumee : cela couvre Python dans ce processus. Un binaire lance hors
Python, ou un interpreteur qui ne charge pas ce module, passe a cote. Pour un
verrou non contournable il faut une politique systeme (AppLocker/WDAC) ou un
shim dans le PATH/devant le binaire — pas un mecanisme applicatif.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

_installe = False
_agent = "python"
_originaux = {}


class CommandeRefusee(PermissionError):
    """Leve quand une commande sensible n'a pas d'approbation valide."""


def _texte_de(args):
    if isinstance(args, (list, tuple)):
        return " ".join(str(a) for a in args)
    return str(args)


def _verifier(args, quoi="commande"):
    """Autorise, ou leve. Consomme l'approbation si elle correspond exactement."""
    import broker
    commande = _texte_de(args)
    risque, motif = broker.classify(commande)
    if risque is None:
        return
    ident = (os.environ.get("SOC_APPROVAL_ID") or "").strip()
    if ident:
        demande = broker.get(ident)
        if demande and demande["status"] == "approved" and \
                demande["action"].strip() == commande.strip():
            if broker.claim(ident, "shield:%s" % _agent):
                return
            raise CommandeRefusee("[shield] approbation %s deja consommee" % ident)
        raise CommandeRefusee(
            "[shield] %s sensible (%s) : l'approbation %s ne correspond pas a cette commande"
            % (quoi, motif, ident))
    raise CommandeRefusee(
        "[shield] %s sensible bloquee (%s) : %r\n"
        "  Demande l'autorisation : python broker.py request --action %r --details \"...\"\n"
        "  puis relance avec SOC_APPROVAL_ID=<id> une fois approuvee."
        % (quoi, motif, commande, commande))


def install(agent="python", audit_log=True):
    """Remplace subprocess.* et os.system dans le processus courant."""
    global _installe, _agent
    if _installe:
        return
    _agent = agent
    _originaux["run"] = subprocess.run
    _originaux["Popen"] = subprocess.Popen
    _originaux["call"] = subprocess.call
    _originaux["check_output"] = subprocess.check_output
    _originaux["system"] = os.system

    def run(args, *a, **k):
        if not k.get("shell"):
            _verifier(args)
        else:
            _verifier(args, "commande shell")
        return _originaux["run"](args, *a, **k)

    class Popen(_originaux["Popen"]):
        def __init__(self, args, *a, **k):
            _verifier(args, "processus")
            super().__init__(args, *a, **k)

    def call(args, *a, **k):
        _verifier(args)
        return _originaux["call"](args, *a, **k)

    def check_output(args, *a, **k):
        _verifier(args)
        return _originaux["check_output"](args, *a, **k)

    def system(commande):
        _verifier(commande, "os.system")
        return _originaux["system"](commande)

    subprocess.run = run
    subprocess.Popen = Popen
    subprocess.call = call
    subprocess.check_output = check_output
    os.system = system
    _installe = True
    if audit_log:
        print("[shield] garde-fou actif pour l'agent %r" % agent)


def uninstall():
    """Retablit les fonctions d'origine (tests, ou desactivation explicite)."""
    global _installe
    if not _installe:
        return
    subprocess.run = _originaux["run"]
    subprocess.Popen = _originaux["Popen"]
    subprocess.call = _originaux["call"]
    subprocess.check_output = _originaux["check_output"]
    os.system = _originaux["system"]
    _installe = False


if __name__ == "__main__":
    install(agent="cli")
    print("garde-fou installe ; teste une commande sensible :")
    try:
        subprocess.run(["docker", "rm", "-f", "x"], capture_output=True)
    except CommandeRefusee as exc:
        print("bloque :", str(exc).splitlines()[0])
