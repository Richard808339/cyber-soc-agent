#!/bin/sh
# Demande un jeton de LECTURE a l'API Wazuh (JWT valable ~15 minutes).
# Usage :  sh read_token.sh [utilisateur] [mot_de_passe]
# Defauts : soc-reader / Lecture-SOC-2026
API=https://localhost:55000
USER=${1:-soc-reader}
PASS=${2:-Lecture-SOC-2026}

JWT=$(wsl.exe -d wazuh -e sh -c "curl -sk -X POST -u '$USER:$PASS' $API/security/user/authenticate | grep -o '\"token\": *\"[^\"]*\"' | cut -d'\"' -f4" 2>/dev/null | tr -d '\r\n')

if [ -z "$JWT" ]; then
  echo "ECHEC : pas de jeton. Verifier que l'API repond :" >&2
  echo "  wsl -d wazuh -e sh -c 'curl -sk -o /dev/null -w \"%{http_code}\" -u wazuh-wui:... -X POST https://localhost:55000/security/user/authenticate'" >&2
  echo "Et que le compte existe : curl ... /security/users?search=$USER" >&2
  exit 1
fi

echo "utilisateur : $USER"
echo "expire dans  : 900 s (15 min, valeur par defaut de l'API Wazuh)"
echo
echo "$JWT"
