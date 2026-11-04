#!/usr/bin/env python3
"""Inventaire des actifs : la liste de ce qui a le droit d'etre sur le reseau.

Sans cette liste, « nouvel appareil » ne veut rien dire : network_watch.py
considerait connu tout appareil deja vu une fois, y compris un intrus. Ici on
declare ce qui est legitime ; le reste est hors inventaire.

Usage :
    python assets.py list
    python assets.py add --mac d4-01-c3-c3-bc-c6 --ip 10.10.10.1 \\
        --hostname mikrotik-gw --type mikrotik_router --note "passerelle"
    python assets.py import-arp          # declare tout ce qui est vu maintenant
    python assets.py remove --mac aa-bb-cc-dd-ee-55
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import broker  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname    TEXT,
    ip          TEXT,
    mac         TEXT UNIQUE,
    device_type TEXT,
    status      TEXT NOT NULL DEFAULT 'actif',
    note        TEXT,
    created_at  TEXT NOT NULL,
    last_seen   TEXT
);
"""

TYPES = ("mikrotik_router", "routeur", "switch", "ap", "serveur", "poste",
         "imprimante", "iot", "vpn", "inconnu")


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init():
    with broker.connect() as conn:
        conn.executescript(SCHEMA)


def normaliser_mac(mac):
    return (mac or "").strip().lower().replace(":", "-")


def ajouter(mac, ip=None, hostname=None, device_type="inconnu", note=None):
    mac = normaliser_mac(mac)
    if len(mac) != 17:
        raise ValueError("adresse MAC invalide : %r" % mac)
    init()
    with broker.connect() as conn:
        conn.execute(
            "INSERT INTO assets (hostname, ip, mac, device_type, status, note, created_at) "
            "VALUES (?,?,?,?, 'actif', ?, ?) "
            "ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip, hostname=excluded.hostname, "
            "device_type=excluded.device_type, note=excluded.note",
            (hostname, ip, mac, device_type, note, _now()))
    return mac


def retirer(mac):
    mac = normaliser_mac(mac)
    with broker.connect() as conn:
        cur = conn.execute("DELETE FROM assets WHERE mac = ?", (mac,))
        return cur.rowcount == 1


def lister(actifs_seulement=True):
    init()
    with broker.connect() as conn:
        sql = "SELECT * FROM assets"
        if actifs_seulement:
            sql += " WHERE status = 'actif'"
        rows = conn.execute(sql + " ORDER BY device_type, hostname, ip").fetchall()
    return [dict(r) for r in rows]


def macs_declarees():
    return {r["mac"] for r in lister()}


def importer_arp(arp, device_type="inconnu"):
    """Declare d'un coup tout ce que l'ARP voit : base de depart, a relire apres."""
    ajoutes = []
    for mac, ip in sorted(arp.items()):
        if mac not in macs_declarees():
            ajouter(mac, ip=ip, device_type=device_type, note="importe de l'ARP")
            ajoutes.append((mac, ip))
    return ajoutes


def main():
    ap = argparse.ArgumentParser(description="Inventaire des actifs du SOC")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="lister les actifs declares")

    p = sub.add_parser("add", help="declarer un actif")
    p.add_argument("--mac", required=True)
    p.add_argument("--ip")
    p.add_argument("--hostname")
    p.add_argument("--type", default="inconnu", choices=TYPES)
    p.add_argument("--note")

    p = sub.add_parser("remove", help="retirer un actif")
    p.add_argument("--mac", required=True)

    sub.add_parser("import-arp", help="declarer tout ce que l'ARP voit maintenant")

    args = ap.parse_args()
    broker.load_dotenv()
    init()

    if args.cmd == "list":
        actifs = lister()
        if not actifs:
            print("aucun actif declare")
        for a in actifs:
            print("%-18s %-15s %-10s %-18s %s" % (a["mac"], a["ip"] or "-",
                                                  a["device_type"], a["hostname"] or "-",
                                                  a["note"] or ""))
    elif args.cmd == "add":
        mac = ajouter(args.mac, args.ip, args.hostname, args.type, args.note)
        print("declare : %s" % mac)
    elif args.cmd == "remove":
        print("retire" if retirer(args.mac) else "introuvable")
    elif args.cmd == "import-arp":
        import network_watch
        ajoutes = importer_arp(network_watch.arp_table())
        for mac, ip in ajoutes:
            print("declare : %s (%s)" % (ip, mac))
        print("%d actif(s) ajoute(s)" % len(ajoutes))
    return 0


if __name__ == "__main__":
    sys.exit(main())
