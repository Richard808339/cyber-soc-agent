#!/bin/sh
# Installe le garde-fou docker dans la distro WSL (a lancer DEPUIS la distro).
#
#   wsl -d wazuh -e sh /mnt/c/Users/HP/Documents/security/soc-dashboard/tools/install-docker-shim.sh
#
# Desinstallation : rm /usr/local/bin/docker
set -eu

ICI=$(cd "$(dirname "$0")" && pwd)
SOURCE="$ICI/docker-shim.sh"
CIBLE=/usr/local/bin/docker

if [ ! -f "$SOURCE" ]; then
    echo "source introuvable : $SOURCE" >&2
    exit 1
fi
if [ ! -x /usr/bin/docker ]; then
    echo "/usr/bin/docker introuvable : rien a envelopper" >&2
    exit 1
fi

install -m 0755 "$SOURCE" "$CIBLE"
echo "installe : $CIBLE (docker reel : /usr/bin/docker)"
echo "resolution dans le PATH : $(command -v docker)"
echo "desinstallation : rm $CIBLE"
