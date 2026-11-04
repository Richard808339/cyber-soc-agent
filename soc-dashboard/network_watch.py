#!/usr/bin/env python3
"""Surveillance du reseau local : inventaire et detection de nouvel equipement.

Source : table ARP de l'hote (aucun identifiant, aucune exposition). Chaque
relevé est compare a l'inventaire connu ; un appareil jamais vu devient un
constat remonte par le tableau de bord et par Telegram.

Limite honnete : l'ARP ne voit que ce que l'hote a contacte recemment, et un
appareil qui change de MAC reste invisible. Pour le LAN complet, il faut
interroger le routeur (MikroTik : /ip/arp, /ip/dhcp-server/lease) - voir README.

Usage :
    python network_watch.py            # inventaire + constats
    python network_watch.py --json     # sortie brute
    python network_watch.py --forget   # efface l'inventaire connu
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import broker  # noqa: E402  (SQLite partage, tables dediees)

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

MULTICAST = ("ff-ff-ff-ff-ff-ff", "01-00-5e", "33-33-", "01-80-c2")

SCHEMA = """
CREATE TABLE IF NOT EXISTS net_devices (
    mac        TEXT PRIMARY KEY,
    ip         TEXT,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    vu         INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS net_oui (
    prefix     TEXT PRIMARY KEY,
    vendor     TEXT,
    fetched_at TEXT
);
"""

OUI_API = "https://api.macvendors.com/%s"


def _maintenant():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init():
    with broker.connect() as conn:
        conn.executescript(SCHEMA)


def vendor(mac, fetch=True, timeout=5):
    """Constructeur a partir du prefixe OUI, avec cache local.

    Reseau indisponible ou prefixe inconnu : retourne None, sans bloquer la
    collecte. Le prefixe est memorise pour ne pas reinterroger l'API a chaque fois.
    """
    if not mac or len(mac) < 8:
        return None
    prefixe = mac[:8].replace("-", ":").upper()
    init()
    with broker.connect() as conn:
        ligne = conn.execute("SELECT vendor FROM net_oui WHERE prefix = ?", (prefixe,)).fetchone()
        if ligne is not None:
            return ligne["vendor"] if ligne["vendor"] != "-" else None
    nom = None
    if fetch:
        try:
            req = urllib.request.Request(OUI_API % prefixe,
                                         headers={"User-Agent": "soc-dashboard/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as rep:
                nom = rep.read().decode("utf-8", "replace").strip()[:60] or None
        except Exception:
            nom = None
    with broker.connect() as conn:
        conn.execute("INSERT INTO net_oui (prefix, vendor, fetched_at) VALUES (?,?,?) "
                     "ON CONFLICT(prefix) DO UPDATE SET vendor=excluded.vendor, "
                     "fetched_at=excluded.fetched_at",
                     (prefixe, nom or "-", _maintenant()))
    return nom


def parse_arp(sortie):
    """Extrait {mac: ip} d'une table ARP texte (Windows `arp -a` ou Linux)."""
    trouve = {}
    for ligne in (sortie or "").splitlines():
        morceaux = ligne.split()
        if len(morceaux) < 2:
            continue
        ip, mac = morceaux[0], morceaux[1].lower().replace(":", "-")
        if ip.count(".") != 3 or len(mac) != 17:
            continue
        if any(mac.startswith(p) for p in MULTICAST) or ip.startswith("224.") \
                or ip.startswith("239.") or ip.endswith(".255") or ip == "255.255.255.255":
            continue
        trouve[mac] = ip
    return trouve


def arp_table():
    """Retourne {mac: ip} depuis `arp -a` de l'hote."""
    try:
        proc = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                              timeout=30, encoding="utf-8", errors="replace")
        return parse_arp(proc.stdout or "")
    except Exception:
        return {}


def inventorier(arp=None, maintenant=None, resoudre_constructeur=True):
    """Compare l'ARP aux appareils connus. Retourne un resume + les nouveaux.

    Les constructeurs sont resolus AVANT la transaction d'ecriture : ouvrir une
    seconde connexion pendant l'ecriture donne « database is locked ».
    """
    init()
    arp = arp if arp is not None else arp_table()
    maintenant = maintenant or _maintenant()

    with broker.connect() as conn:
        connus = {r["mac"] for r in conn.execute("SELECT mac FROM net_devices")}
    a_ajouter = {mac: ip for mac, ip in arp.items() if mac not in connus}
    constructeurs = {}
    for mac in a_ajouter:
        constructeurs[mac] = vendor(mac) if resoudre_constructeur else None

    nouveaux = []
    with broker.connect() as conn:
        for mac, ip in sorted(arp.items()):
            if mac in a_ajouter:
                conn.execute("INSERT INTO net_devices (mac, ip, first_seen, last_seen) "
                             "VALUES (?,?,?,?)", (mac, ip, maintenant, maintenant))
                nouveaux.append({"mac": mac, "ip": ip, "constructeur": constructeurs.get(mac)})
            else:
                conn.execute("UPDATE net_devices SET ip = ?, last_seen = ?, vu = vu + 1 "
                             "WHERE mac = ?", (ip, maintenant, mac))
        tota = conn.execute("SELECT COUNT(*) AS n FROM net_devices").fetchone()["n"]
    return {"total_connus": tota, "vus_maintenant": len(arp), "nouveaux": nouveaux}


def oublier():
    with broker.connect() as conn:
        conn.executescript(SCHEMA)
        conn.execute("DELETE FROM net_devices")


def appareils(limite=30):
    with broker.connect() as conn:
        conn.executescript(SCHEMA)
        rows = conn.execute("SELECT * FROM net_devices ORDER BY last_seen DESC LIMIT ?",
                            (limite,)).fetchall()
    return [dict(r) for r in rows]


def main():
    ap = argparse.ArgumentParser(description="Surveillance du reseau local")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--forget", action="store_true", help="efface l'inventaire connu")
    args = ap.parse_args()
    broker.init()
    broker.load_dotenv()

    if args.forget:
        oublier()
        print("inventaire efface")
        return 0

    res = inventorier()
    if args.json:
        print(json.dumps({"resume": res, "appareils": appareils()},
                         ensure_ascii=False, indent=2))
        return 0

    print("appareils connus : %d | vus maintenant : %d" % (res["total_connus"],
                                                           res["vus_maintenant"]))
    for n in res["nouveaux"]:
        print("  nouveau : %s (%s)" % (n["ip"], n["mac"]))
    if not res["nouveaux"]:
        print("  aucun nouvel appareil")
    return 0


if __name__ == "__main__":
    sys.exit(main())
