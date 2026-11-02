#!/bin/sh
# Garde-fou docker cote WSL (a installer en /usr/local/bin/docker).
#
# Objectif : un agent, un script ou toi-meme ne pouvez plus detruire un conteneur
# de la pile sans une approbation humaine enregistree par le broker Windows.
#
# Principe : les commandes de lecture passent telles quelles. Les verbes
# destructeurs exigent SOC_APPROVAL_ID pointant vers une demande approuvee,
# dont l'action correspond exactement (une seule fois).
#
# Contournement possible : appeler /usr/bin/docker directement, ou modifier ce
# fichier (tu es root). C'est une barriere, pas un coffre-fort.
set -u

REAL=/usr/bin/docker
SOC_DIR=${SOC_SHIM_DIR:-/mnt/c/Users/HP/Documents/security/soc-dashboard}
LOG=${SOC_SHIM_LOG:-/var/log/soc-docker-shim.log}
PY=${SOC_SHIM_PYTHON:-/usr/bin/python3}

journal() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG" 2>/dev/null; }

# Le verbe detruit-il quelque chose ?
sensible() {
    case "$1" in
        rm|rmi|stop|kill|restart|pause|unpause) return 0 ;;
        prune) return 0 ;;
        system) case "${2:-}" in prune) return 0 ;; esac; return 1 ;;
        compose|stack) case "${2:-}" in down|stop|rm|kill|restart) return 0 ;; esac; return 1 ;;
        container|volume|network|image|plugin|node|service) case "${2:-}" in rm|prune) return 0 ;; esac; return 1 ;;
    esac
    return 1
}

if [ "$#" -eq 0 ]; then
    exec "$REAL"
fi

commande="docker $*"

if sensible "$1" "${2:-}"; then
    aide="${SOC_APPROVAL_ID:-}"
    if [ -z "$aide" ]; then
        journal "REFUS (sans approbation) : $commande"
        cat >&2 <<EOF
[garde-fou docker] action destructive bloquee : $commande

  Aucune approbation fournie. Pour l'autoriser :
    1. cote Windows  : cd C:\\Users\\HP\\Documents\\security\\soc-dashboard
                       python broker.py request --action "wsl -d wazuh -e $commande" --details "..."
    2. approuver la demande dans Telegram
    3. relancer ici  : SOC_APPROVAL_ID=<id> $commande
EOF
        exit 126
    fi
    if [ ! -x "$PY" ]; then
        journal "REFUS (python3 absent) : $commande"
        echo "[garde-fou docker] python3 introuvable : impossible de verifier l'approbation" >&2
        exit 126
    fi
    "$PY" - "$aide" "$commande" "$SOC_DIR" <<'PYCODE'
import sys
sys.path.insert(0, sys.argv[3])
try:
    import broker
except Exception as exc:
    sys.stderr.write("[garde-fou docker] broker inaccessible : %s\n" % exc)
    sys.exit(6)
aide, commande = sys.argv[1], sys.argv[2]
demande = broker.get(aide)
if not demande:
    sys.stderr.write("[garde-fou docker] approbation inconnue : %s\n" % aide)
    sys.exit(3)
if demande["status"] != "approved":
    sys.stderr.write("[garde-fou docker] approbation %s en statut %s\n" % (aide, demande["status"]))
    sys.exit(4)
if broker.normalize(demande["action"]).strip() != commande.strip():
    sys.stderr.write("[garde-fou docker] approbation %s ne couvre pas : %s\n"
                     % (aide, commande))
    sys.exit(5)
sys.exit(0 if broker.claim(aide, "shim:wsl") else 7)
PYCODE
    rc=$?
    if [ "$rc" -ne 0 ]; then
        journal "REFUS (approbation invalide rc=$rc) : $commande"
        exit 126
    fi
    journal "AUTORISE (approbation ${aide}) : $commande"
fi

exec "$REAL" "$@"
