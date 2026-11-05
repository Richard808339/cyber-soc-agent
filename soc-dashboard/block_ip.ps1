<#
.SYNOPSIS
    Bloque ou debloque une adresse IP dans le pare-feu Windows, avec validation stricte.

.DESCRIPTION
    Ecrit pour etre appele par le broker d'autorisation du SOC (approbation humaine
    obligatoire) et non directement par un webhook.

    Differences avec un script naif :
      - l'adresse est validee avant tout appel (une valeur comme "-" ou "*" ferait
        bloquer tout le trafic) ;
      - les adresses locales, privees et de documentation sont refusees par defaut :
        bloquer sa propre passerelle coupe le poste du reseau ;
      - la regle est idempotente et nommee de facon deterministe ;
      - le script sort avec un code d'erreur explicite (0 succes, 2 entree invalide,
        3 privileges manquants, 4 echec de creation) : un script qui fait `exit` sans
        code est un script qui ment a son appelant ;
      - la sortie est du JSON sur une ligne, lisible par un appelant automatise.

.EXAMPLE
    powershell -NoProfile -File block_ip.ps1 -IpAddress 198.51.100.23 -Reason "brute force SSH"

.EXAMPLE
    powershell -NoProfile -File block_ip.ps1 -IpAddress 198.51.100.23 -Action Unblock
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$IpAddress,

    [ValidateSet('Block', 'Unblock')]
    [string]$Action = 'Block',

    [ValidateSet('Inbound', 'Outbound', 'Both')]
    [string]$Direction = 'Inbound',

    [string]$Reason = 'IOC signale par le SOC',

    [switch]$AllowPrivate,

    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'

function Repondre {
    param([hashtable]$Donnees, [int]$CodeSortie)
    $Donnees['ip'] = $IpAddress
    $Donnees['action'] = $Action
    ([pscustomobject]$Donnees | ConvertTo-Json -Compress)
    exit $CodeSortie
}

function Test-Privileges {
    $identite = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identite)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- 1. validation de l'entree ------------------------------------------------
$adresse = $null
$portee = $IpAddress.Trim()
if ($portee -match '^(?<ip>[^/]+)/(?<bits>\d{1,3})$') {
    if ($Matches['bits'] -ne '32') {
        Repondre @{ statut = 'refuse'; motif = 'seule une adresse seule ou un /32 est accepte' } 2
    }
    $portee = $Matches['ip']
}

if (-not [System.Net.IPAddress]::TryParse($portee, [ref]$adresse)) {
    Repondre @{ statut = 'refuse'; motif = 'adresse IP invalide' } 2
}

if ($adresse.AddressFamily -eq 'InterNetworkV6' -and $adresse.IsIPv4MappedToIPv6) {
    $adresse = $adresse.MapToIPv4()
}

$interdits = @()
if ([System.Net.IPAddress]::IsLoopback($adresse)) { $interdits += 'boucle locale' }
if ($adresse.IsIPv6LinkLocal) { $interdits += 'adresse lien-local' }
if ($adresse.IsIPv6Multicast -or $adresse.IsIPv6SiteLocal) { $interdits += 'adresse de groupe ou de site' }
if (-not $AllowPrivate) {
    $octets = $adresse.GetAddressBytes()
    if ($adresse.AddressFamily -eq 'InterNetwork') {
        if ($octets[0] -eq 10) { $interdits += 'plage privee 10.0.0.0/8' }
        if ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) { $interdits += 'plage privee 172.16.0.0/12' }
        if ($octets[0] -eq 192 -and $octets[1] -eq 168) { $interdits += 'plage privee 192.168.0.0/16' }
        if ($octets[0] -eq 169 -and $octets[1] -eq 254) { $interdits += 'plage lien-local / APIPA' }
        if ($octets[0] -eq 127) { $interdits += 'boucle locale' }
        if ($octets[0] -eq 0) { $interdits += 'adresse non specifiee' }
        if ($octets[0] -ge 224) { $interdits += 'multicast ou reserve' }
    }
}

$interdits = $interdits | Select-Object -Unique

if ($interdits.Count -gt 0) {
    Repondre @{ statut = 'refuse'; motif = ('adresse locale ou protegee : ' + ($interdits -join ', ')) } 2
}

# --- 2. cibles et noms de regles ---------------------------------------------
$ip = $adresse.ToString()
$suffixe = ($ip -replace '[:.]', '-')
$cibles = switch ($Direction) {
    'Inbound' { @('in') }
    'Outbound' { @('out') }
    'Both' { @('in', 'out') }
}

# --- 3. privileges ------------------------------------------------------------
if (-not $WhatIf -and -not (Test-Privileges)) {
    Repondre @{ statut = 'privileges'; motif = 'execution en administrateur requise pour modifier le pare-feu' } 3
}

# --- 4. application -----------------------------------------------------------
$resultats = @()
$code = 0
foreach ($sens in $cibles) {
    $nom = "SOC-Block-$suffixe-$sens"
    $existe = Get-NetFirewallRule -Name $nom -ErrorAction SilentlyContinue

    if ($Action -eq 'Unblock') {
        if (-not $existe) {
            $resultats += @{ regle = $nom; statut = 'absent' }
            continue
        }
        if ($WhatIf) {
            $resultats += @{ regle = $nom; statut = 'simule_suppression' }
            continue
        }
        try {
            Remove-NetFirewallRule -Name $nom -ErrorAction Stop
            $resultats += @{ regle = $nom; statut = 'supprime' }
        } catch {
            $resultats += @{ regle = $nom; statut = 'echec'; motif = $_.Exception.Message }
            $code = 4
        }
        continue
    }

    if ($existe) {
        $resultats += @{ regle = $nom; statut = 'deja_bloque' }
        continue
    }

    if ($WhatIf) {
        $resultats += @{ regle = $nom; statut = 'simule' }
        continue
    }

    try {
        New-NetFirewallRule `
            -Name $nom `
            -DisplayName "SOC Block $ip ($sens)" `
            -Description $Reason `
            -Direction $(if ($sens -eq 'in') { 'Inbound' } else { 'Outbound' }) `
            -Action Block `
            -RemoteAddress $ip `
            -Profile Any `
            -Enabled True -ErrorAction Stop | Out-Null

        $verif = Get-NetFirewallRule -Name $nom -ErrorAction SilentlyContinue
        $resultats += @{ regle = $nom; statut = $(if ($verif) { 'bloque' } else { 'introuvable_apres_creation' }) }
        if (-not $verif) { $code = 4 }
    } catch {
        $resultats += @{ regle = $nom; statut = 'echec'; motif = $_.Exception.Message }
        $code = 4
    }
}

Repondre @{
    statut = $(if ($code -eq 0) { 'ok' } else { 'echec_partiel' })
    simulation = [bool]$WhatIf
    raison = $Reason
    resultats = $resultats
} $code
