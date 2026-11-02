"""Catalogue de pistes de reponse (playbooks) pour le SOC.

Chaque playbook associe une famille d'alertes Wazuh a des etapes de reponse
concretes et des commandes pretes a copier. Aucune commande n'est executee :
le tableau de bord les affiche, l'analyste decide.
"""

PLAYBOOKS = {
    "brute_force": {
        "title": "Force brute sur un service d'authentification",
        "why": "Repetition d'echecs d'authentification depuis une meme source : "
               "tentative de deviner des identifiants (SSH, RDP, SMB, web).",
        "urgency": "haute",
        "mitre": ["T1110 Brute Force"],
        "steps": [
            "Identifier la source exacte (IP, compte vise) dans les alertes brutes.",
            "Verifier si une connexion a fini par reussir apres les echecs : c'est le signal d'une compromission.",
            "Bloquer la source au pare-feu du poste ou du reseau.",
            "Verifier le verrouillage de compte et la politique de mot de passe.",
            "Si succes apres echecs : isoler le poste, changer le mot de passe, chercher la persistance.",
        ],
        "commands": [
            {"label": "Bloquer l'IP (Windows, admin)",
             "os": "windows",
             "cmd": 'New-NetFirewallRule -DisplayName "SOC-Block-<IP>" -Direction Inbound -RemoteAddress <IP> -Action Block'},
            {"label": "Bloquer l'IP (Linux, agent)",
             "os": "linux",
             "cmd": "sudo ufw deny from <IP> to any"},
            {"label": "Compter les echecs par compte et par IP (24 h)",
             "os": "wazuh",
             "cmd": "curl -sk -u admin:'<INDEXER_PASS>' -H 'Content-Type: application/json' https://localhost:9200/wazuh-alerts-*/_search?size=0 -d '{\"query\":{\"query_string\":{\"query\":\"rule.description:*Failure*\"}},\"aggs\":{\"compte\":{\"terms\":{\"field\":\"data.win.eventdata.targetUserName\",\"size\":10}},\"ip\":{\"terms\":{\"field\":\"data.win.eventdata.ipAddress\",\"size\":10}}}}'"},
            {"label": "Verifier qu'un succes suit les echecs (meme compte)",
             "os": "wazuh",
             "cmd": "curl -sk -u admin:'<INDEXER_PASS>' -H 'Content-Type: application/json' https://localhost:9200/wazuh-alerts-*/_search?size=0 -d '{\"query\":{\"query_string\":{\"query\":\"rule.description:*Logon*\"}},\"aggs\":{\"d\":{\"terms\":{\"field\":\"rule.description\",\"size\":10}}}}'"},
        ],
    },
    "port_scan": {
        "title": "Balayage de ports / reconnaissance",
        "why": "Un poste est scanne ou scanne le reseau : recherche de services exposes "
               "avant une attaque.",
        "urgency": "moyenne",
        "mitre": ["T1046 Network Service Discovery"],
        "steps": [
            "Verifier si la source est interne (poste connu, outil de scan legitime) ou externe.",
            "Identifier les ports ouverts sur la cible : ce sont les surfaces d'attaque reelles.",
            "Fermer les services non necessaires (SMB 445, NetBIOS 139, RDP 3389).",
            "Bloquer la source si elle est inconnue.",
        ],
        "commands": [
            {"label": "Lister les ports en ecoute (Windows)",
             "os": "windows",
             "cmd": "Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | Sort-Object LocalPort"},
            {"label": "Desactiver SMBv1 et la decouverte NetBIOS",
             "os": "windows",
             "cmd": "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"},
            {"label": "Bloquer 445/139 en entree",
             "os": "windows",
             "cmd": 'New-NetFirewallRule -DisplayName "SOC-Block-SMB" -Direction Inbound -LocalPort 445,139 -Protocol TCP -Action Block'},
        ],
    },
    "fim_change": {
        "title": "Integrite de fichier modifiee (FIM / syscheck)",
        "why": "Un fichier surveille a change (binaire systeme, configuration, web root) : "
               "signature classique d'une persistance ou d'une elevation de privileges.",
        "urgency": "haute",
        "mitre": ["T1543 Create or Modify System Process", "T1547 Boot or Logon Autostart"],
        "steps": [
            "Identifier le fichier, l'ancien et le nouveau hash, et le compte qui a ecrit.",
            "Comparer avec une baseline saine ou l'installateur d'origine.",
            "Chercher l'export du fichier (copie hors du poste) pour analyse.",
            "Si le fichier est un binaire systeme : restaurer depuis une source sure et isoler le poste.",
        ],
        "commands": [
            {"label": "Hash et signature du fichier (Windows)",
             "os": "windows",
             "cmd": "Get-FileHash -Algorithm SHA256 '<CHEMIN>'; Get-AuthenticodeSignature '<CHEMIN>'"},
            {"label": "Copier l'echantillon pour analyse",
             "os": "windows",
             "cmd": "Copy-Item '<CHEMIN>' \"$env:USERPROFILE\\Desktop\\soc-sample-$((Get-Date).ToString('yyyyMMdd-HHmm')).bin\""},
            {"label": "Quarantaine Defender sur le fichier",
             "os": "windows",
             "cmd": "Start-MpScan -ScanType CustomScan -ScanPath '<DOSSIER>'"},
        ],
    },
    "vulnerability": {
        "title": "Vulnerabilite critique detectee",
        "why": "Le scanner de vulnerabilites Wazuh a trouve une CVE exploitable sur un poste "
               "ou une dependance installee.",
        "urgency": "haute",
        "mitre": ["T1190 Exploit Public-Facing Application"],
        "steps": [
            "Lire la CVE, le paquet touche et la version installee.",
            "Verifier si le service concerne est expose au reseau (port en ecoute).",
            "Appliquer la mise a jour ou desactiver le service en attendant.",
            "Re-scanner apres correctif pour confirmer la disparition de l'alerte.",
        ],
        "commands": [
            {"label": "Mettre a jour tous les paquets (Windows)",
             "os": "windows",
             "cmd": "winget upgrade --all --include-unknown --accept-source-agreements --accept-package-agreements"},
            {"label": "Poste Linux",
             "os": "linux",
             "cmd": "sudo apt-get update && sudo apt-get -y upgrade   # ou sudo dnf -y upgrade"},
            {"label": "Lister les vulnerabilites par severite (indexer)",
             "os": "wazuh",
             "cmd": "curl -sk -u admin:'<INDEXER_PASS>' -H 'Content-Type: application/json' https://localhost:9200/wazuh-states-vulnerabilities-*/_search?size=0 -d '{\"aggs\":{\"sev\":{\"terms\":{\"field\":\"vulnerability.severity\"}}}}'"},
        ],
    },
    "malware": {
        "title": "Malware / code malveillant signale",
        "why": "Signature antivirus, YARA ou detection heuristique sur un fichier ou un processus.",
        "urgency": "critique",
        "mitre": ["T1204 User Execution", "T1059 Command and Scripting Interpreter"],
        "steps": [
            "Isoler le poste du reseau (le garder allume pour l'analyse).",
            "Lancer un scan complet et relever les detections.",
            "Identifier le vecteur d'entree (mail, telechargement, cle USB).",
            "Ne pas supprimer avant d'avoir exporte les artefacts si une investigation est requise.",
        ],
        "commands": [
            {"label": "Isoler le poste (couper le reseau applicatif)",
             "os": "windows",
             "cmd": "Disable-NetAdapter -Name '<NOM_CARTE>' -Confirm:$false"},
            {"label": "Scan complet Defender",
             "os": "windows",
             "cmd": "Start-MpScan -ScanType FullScan; Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 10"},
            {"label": "Historique des menaces",
             "os": "windows",
             "cmd": "Get-MpThreat | Select-Object ThreatName,SeverityID,IsActive | Format-Table -AutoSize"},
        ],
    },
    "agent_down": {
        "title": "Poste injoignable (agent deconnecte)",
        "why": "Un agent ne remonte plus d'evenements : poste eteint, reseau coupe, "
               "agent arrete ou desinstalle. C'est aussi un angle mort de la surveillance.",
        "urgency": "moyenne",
        "mitre": ["T1562 Impair Defenses"],
        "steps": [
            "Verifier que le poste est allume et joignable (ping, partage admin).",
            "Verifier le service Wazuh sur le poste et les ports 1514/1515 vers le manager.",
            "Redemarrer l'agent et confirmer le retour dans la liste des postes actifs.",
            "Si l'agent a ete desinstalle volontairement : documenter l'exception.",
        ],
        "commands": [
            {"label": "Etat de l'agent (Windows)",
             "os": "windows",
             "cmd": "Get-Service WazuhSvc | Select-Object Status,StartType,Name; Get-Content 'C:\\Program Files (x86)\\ossec-agent\\ossec.log' -Tail 30"},
            {"label": "Redemarrer l'agent",
             "os": "windows",
             "cmd": "Restart-Service WazuhSvc"},
            {"label": "Test de connectivite vers le manager",
             "os": "windows",
             "cmd": "Test-NetConnection -ComputerName <MANAGER> -Port 1514"},
        ],
    },
    "auth_anomaly": {
        "title": "Authentification inhabituelle (succes suspect)",
        "why": "Connexion reussie hors horaires, depuis une source nouvelle, ou apres "
               "plusieurs echecs : possible vol d'identifiants (T1078).",
        "urgency": "moyenne",
        "mitre": ["T1078 Valid Accounts"],
        "steps": [
            "Verifier avec l'utilisateur si la connexion est legitime (canal separe).",
            "Comparer l'heure et la source avec l'historique du compte.",
            "Chercher les actions faites juste apres la connexion (processus, fichiers, reseau).",
            "Si non legitime : reinitialiser le mot de passe, revoquer les sessions, activer le MFA.",
        ],
        "commands": [
            {"label": "Sessions et derniers logons (Windows)",
             "os": "windows",
             "cmd": "Get-LocalUser | Select-Object Name,Enabled,LastLogon; query user"},
            {"label": "Forcer la reinitialisation du mot de passe",
             "os": "windows",
             "cmd": "Set-LocalUser -Name '<COMPTE>' -Password (Read-Host -AsSecureString 'Nouveau mot de passe')"},
            {"label": "Historique du compte dans Wazuh (indexer)",
             "os": "wazuh",
             "cmd": "curl -sk -u admin:'<INDEXER_PASS>' -H 'Content-Type: application/json' https://localhost:9200/wazuh-alerts-*/_search?size=20 -d '{\"query\":{\"bool\":{\"must\":[{\"match_phrase\":{\"data.win.eventdata.targetUserName\":\"<COMPTE>\"}}]}},\"sort\":[{\"timestamp\":\"desc\"}]}'"},
        ],
    },
    "priv_esc": {
        "title": "Elevation de privileges / ajout de compte",
        "why": "Creation de compte administrateur, ajout a un groupe privilegie ou "
               "modification de politique de securite.",
        "urgency": "critique",
        "mitre": ["T1136 Create Account", "T1098 Account Manipulation"],
        "steps": [
            "Identifier le compte createur et le compte cree.",
            "Verifier si l'action vient d'un processus legitime (installateur, GPO).",
            "Desactiver le compte suspect et retirer les privileges.",
            "Chercher les autres actions du compte createur sur 24 h.",
        ],
        "commands": [
            {"label": "Membres du groupe administrateurs",
             "os": "windows",
             "cmd": "Get-LocalGroupMember -Group Administrateurs -ErrorAction SilentlyContinue; Get-LocalGroupMember -Group Administrators"},
            {"label": "Comptes locaux recents",
             "os": "windows",
             "cmd": "Get-LocalUser | Sort-Object -Property * -Descending | Select-Object -First 10 Name,Enabled,LastLogon"},
            {"label": "Desactiver un compte",
             "os": "windows",
             "cmd": "Disable-LocalUser -Name '<COMPTE>'"},
        ],
    },
    "generic_high": {
        "title": "Alerte de severite elevee a trier",
        "why": "Alerte au-dessus du seuil de gravite sans playbook specifique identifie.",
        "urgency": "haute",
        "mitre": [],
        "steps": [
            "Lire la description et le log complet de l'alerte.",
            "Identifier le poste, l'heure et l'utilisateur concernes.",
            "Correler avec les autres alertes du meme poste dans l'heure precedente.",
            "Classer : faux positif documente, incident a traiter, ou escalade.",
        ],
        "commands": [
            {"label": "Contexte du poste dans Wazuh (API)",
             "os": "wazuh",
             "cmd": "curl -sk -H \"Authorization: Bearer $TOKEN\" 'https://localhost:55000/agents?select=id,name,status,lastKeepAlive'"},
            {"label": "Regles les plus declenchees sur 24 h",
             "os": "wazuh",
             "cmd": "curl -sk -u admin:'<INDEXER_PASS>' -H 'Content-Type: application/json' https://localhost:9200/wazuh-alerts-*/_search?size=0 -d '{\"query\":{\"range\":{\"timestamp\":{\"gte\":\"now-24h\"}}},\"aggs\":{\"r\":{\"terms\":{\"field\":\"rule.description\",\"size\":10}}}}'"},
        ],
    },
}

# Signature -> cle de playbook. L'ordre compte : le premier motif trouve gagne.
_SIGNATURES = [
    ("malware", ("virus", "malware", "trojan", "yara", "rootkit", "malicious", "defender")),
    ("priv_esc", ("admin group", "new user", "account created", "added to group",
                  "privilege", "administrator", "compte cree")),
    ("brute_force", ("brute", "authentication failure", "failed password",
                     "multiple failed", "invalid login", "logon failure", "echec")),
    ("port_scan", ("scan", "port sweep", "reconnaissance", "firewall drop", "dropped")),
    ("fim_change", ("integrity", "checksum", "modified", "syscheck", "file added",
                    "file deleted", "fim")),
    ("vulnerability", ("vulnerab", "cve-", "outdated", "patch", "package")),
    ("agent_down", ("disconnected", "never connected", "agent stopped", "inactive agent")),
    ("auth_anomaly", ("logon success", "login success", "accepted", "session opened",
                      "valid accounts")),
]

# Regles Wazuh connues, mappees directement.
_RULE_IDS = {
    "5710": "brute_force", "5711": "brute_force", "5712": "brute_force",
    "5716": "brute_force", "5720": "brute_force", "60122": "brute_force",
    "550": "fim_change", "5501": "fim_change", "554": "fim_change",
    "510": "rootkit_malware", "511": "malware", "512": "malware",
    "23502": "vulnerability", "23503": "vulnerability", "23504": "vulnerability",
    "60106": "auth_anomaly", "60108": "auth_anomaly", "60112": "auth_anomaly",
    "60110": "priv_esc", "60138": "priv_esc",
    "503": "agent_down", "504": "agent_down", "505": "agent_down",
}


def match(alert):
    """Retourne la cle de playbook la plus pertinente pour une alerte."""
    rule = alert.get("rule") or {}
    rule_id = str(rule.get("id") or alert.get("rule_id") or "")
    if rule_id in _RULE_IDS:
        key = _RULE_IDS[rule_id]
        if key in PLAYBOOKS:
            return key

    haystack = " ".join([
        str(rule.get("description") or alert.get("description") or ""),
        " ".join(rule.get("groups") or alert.get("groups") or []),
        str(alert.get("location") or ""),
    ]).lower()

    for key, needles in _SIGNATURES:
        if any(n in haystack for n in needles):
            return key
    return "generic_high"


def get(key):
    return PLAYBOOKS.get(key) or PLAYBOOKS["generic_high"]


def catalog():
    """Liste compacte pour l'API."""
    return [
        {"key": k, "title": v["title"], "urgency": v["urgency"],
         "steps": len(v["steps"]), "mitre": v["mitre"]}
        for k, v in PLAYBOOKS.items()
    ]
