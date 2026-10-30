# SOC remediation + elevated audit - KOFFI
# PHASE A : CR1 (AnyDesk entrant) + CR2 (signature SMB, NetBIOS 139/137/138)
# PHASE B : releve eleve (BitLocker, TPM, Secure Boot, exclusions Defender, menaces, comptes)
$ErrorActionPreference = 'SilentlyContinue'
$log = 'C:\Users\HP\AppData\Local\hermes\cache\scratch\soc_fix_audit.log'
Start-Transcript -Path $log -Force | Out-Null

function Step($name, $block) {
  "---- $name ----"
  try { & $block } catch { "ECHEC: $($_.Exception.Message)" }
  ""
}

"### DEMARRE $((Get-Date).ToString('dd/MM/yyyy HH:mm:ss')) ###"
"Eleve: $((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"

""
"================ PHASE A : REMEDIATION ================"

Step 'CR1 blocage entrant AnyDesk TCP 7070' {
  $ex = Get-NetFirewallRule -DisplayName 'SOC-CR1 AnyDesk 7070 inbound block' -ErrorAction SilentlyContinue
  if ($ex) { "regle deja presente, mise a jour" ; Set-NetFirewallRule -DisplayName 'SOC-CR1 AnyDesk 7070 inbound block' -Direction Inbound -Action Block -Enabled True -Profile Any }
  else { New-NetFirewallRule -DisplayName 'SOC-CR1 AnyDesk 7070 inbound block' -Direction Inbound -Protocol TCP -LocalPort 7070 -Action Block -Profile Any -Enabled True | Out-Null ; "regle TCP creee" }
  $ex2 = Get-NetFirewallRule -DisplayName 'SOC-CR1 AnyDesk 7070 UDP inbound block' -ErrorAction SilentlyContinue
  if (-not $ex2) { New-NetFirewallRule -DisplayName 'SOC-CR1 AnyDesk 7070 UDP inbound block' -Direction Inbound -Protocol UDP -LocalPort 7070 -Action Block -Profile Any -Enabled True | Out-Null ; "regle UDP creee" }
  Get-NetFirewallRule -DisplayName 'SOC-CR1*' | ForEach-Object { "  $($_.DisplayName) : $($_.Enabled) / $($_.Action)" }
}

Step 'CR2 signature SMB obligatoire' {
  $b = Get-SmbServerConfiguration
  "avant : RequireSecuritySignature=$($b.RequireSecuritySignature) EnableSecuritySignature=$($b.EnableSecuritySignature) EncryptData=$($b.EncryptData)"
  Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force
  $a = Get-SmbServerConfiguration
  "apres : RequireSecuritySignature=$($a.RequireSecuritySignature) EnableSecuritySignature=$($a.EnableSecuritySignature) EncryptData=$($a.EncryptData)"
}

Step 'CR2 blocage NetBIOS entrant 139/137/138' {
  foreach ($p in @(@{n='139';proto='TCP'}, @{n='137';proto='UDP'}, @{n='138';proto='UDP'})) {
    $dn = "SOC-CR2 NetBIOS $($p.n) inbound block"
    if (-not (Get-NetFirewallRule -DisplayName $dn -ErrorAction SilentlyContinue)) {
      New-NetFirewallRule -DisplayName $dn -Direction Inbound -Protocol $p.proto -LocalPort $p.n -Action Block -Profile Any -Enabled True | Out-Null
      "  cree: $dn ($($p.proto))"
    } else { "  deja present: $dn" }
  }
  Get-NetFirewallRule -DisplayName 'SOC-CR2*' | ForEach-Object { "  $($_.DisplayName) : $($_.Enabled) / $($_.Action)" }
}

Step 'VERIFICATION post-remediation' {
  $l = Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in 7070,139,445 }
  if ($l) { $l | ForEach-Object { "  ecoute encore: $($_.LocalAddress):$($_.LocalPort)" } } else { "  aucune ecoute sur 7070/139" }
  "  445 reste en ecoute mais signature desormais obligatoire"
}

""
"================ PHASE B : RELEVE ELEVE ================"

Step 'BITLOCKER' {
  $v = Get-BitLockerVolume -MountPoint 'C:'
  "ProtectionStatus: $($v.ProtectionStatus)  VolumeStatus: $($v.VolumeStatus)  EncryptionPercentage: $($v.EncryptionPercentage)"
  "Protecteurs: $(($v.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ', ')"
}

Step 'DEMARRAGE SECURISE / TPM' {
  "SecureBoot: $(Confirm-SecureBootUEFI)"
  $t = Get-Tpm
  "TPM present: $($t.TpmPresent)  ready: $($t.TpmReady)  enabled: $($t.TpmEnabled)  activated: $($t.TpmActivated)"
  $t2 = Get-CimInstance -Namespace root\cimv2\security\microsofttpm -Class Win32_Tpm
  "TPM spec: $($t2.SpecVersion)  manufacturier: $($t2.ManufacturerVersion)"
}

Step 'DEFENDER EXCLUSIONS + POLITIQUE' {
  $p = Get-MpPreference
  "ExclusionPath: $(if($p.ExclusionPath){$p.ExclusionPath -join ' | '}else{'aucune'})"
  "ExclusionProcess: $(if($p.ExclusionProcess){$p.ExclusionProcess -join ' | '}else{'aucune'})"
  "ExclusionExtension: $(if($p.ExclusionExtension){$p.ExclusionExtension -join ' | '}else{'aucune'})"
  "ExclusionIpAddress: $(if($p.ExclusionIpAddress){$p.ExclusionIpAddress -join ' | '}else{'aucune'})"
  "DisableRealtimeMonitoring: $($p.DisableRealtimeMonitoring)  PUAProtection: $($p.PUAProtection)  EnableNetworkProtection: $($p.EnableNetworkProtection)"
  "ASR regles: $(($p.AttackSurfaceReductionRules_Ids).Count)"
  $d = Get-MpComputerStatus
  "FullScanEndTime: $($d.FullScanEndTime)  QuickScanEndTime: $($d.QuickScanEndTime)  TamperProtection: $($d.IsTamperProtected)"
}

Step 'HISTORIQUE MENACES' {
  $t = Get-MpThreat
  if ($t) { $t | Sort-Object -Property InitialDetectionTime -Descending | Select-Object -First 10 | ForEach-Object { "  $($_.InitialDetectionTime)  $($_.ThreatName)  sev=$($_.SeverityID)  status=$($_.ThreatStatusID)" } } else { "  aucune menace enregistree" }
  $td = Get-MpThreatDetection
  if ($td) { $td | Sort-Object InitialDetectionTime -Descending | Select-Object -First 5 | ForEach-Object { "  detection $($_.InitialDetectionTime) actionOK=$($_.ActionSuccess)" } }
}

Step 'COMPTES' {
  $g = Get-LocalUser -Name Invite
  "Invite actif: $($g.Enabled)"
  Get-LocalUser | ForEach-Object { "  $($_.Name) actif=$($_.Enabled) expire=$($_.PasswordExpires) dernierMdp=$($_.PasswordLastSet)" }
  "Groupes admins:"
  Get-LocalGroupMember -Group Administrateurs | ForEach-Object { "  $($_.Name) [$($_.PrincipalSource)]" }
}

Step 'CONNEXIONS ECHOUES 4625 (7j)' {
  $e = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddDays(-7)}
  if ($e) {
    "total: $($e.Count)"
    $e | Select-Object -First 5 | ForEach-Object { "  $($_.TimeCreated)" }
    $e | ForEach-Object { $_.Properties[5].Value } | Group-Object | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "  compte cible $($_.Name): $($_.Count)" }
  } else { "  aucun echec sur 7 jours" }
}

Step 'EXPOSITION RESEAU (0.0.0.0)' {
  Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -in '0.0.0.0','::' } | ForEach-Object {
    $pr = Get-Process -Id $_.OwningProcess
    "  $($_.LocalPort) <= $($pr.ProcessName) (PID $($_.OwningProcess))"
  } | Sort-Object -Unique
}

""
"### FIN $((Get-Date).ToString('dd/MM/yyyy HH:mm:ss')) ###"
Stop-Transcript | Out-Null
