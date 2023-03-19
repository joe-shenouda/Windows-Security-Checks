# Security Checks PowerShell Script

# Check 1 - Windows Defender Status
$defenderStatus = Get-MpComputerStatus
if ($defenderStatus.AntivirusEnabled) {
    Write-Host "Windows Defender is enabled and running." -ForegroundColor Green
} else {
    Write-Host "Windows Defender is not enabled or not running." -ForegroundColor Red
}

# Check 2 - Firewall Status
$firewallStatus = Get-NetFirewallProfile | Select-Object Name,Enabled
if ($firewallStatus.Enabled) {
    Write-Host "Windows Firewall is enabled and running." -ForegroundColor Green
} else {
    Write-Host "Windows Firewall is not enabled or not running." -ForegroundColor Red
}

# Check 3 - User Account Control (UAC) Status
$uacStatus = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').ConsentPromptBehaviorAdmin
switch ($uacStatus) {
    0 {Write-Host "UAC is disabled." -ForegroundColor Red}
    2 {Write-Host "UAC is set to prompt for consent on the secure desktop." -ForegroundColor Green}
    5 {Write-Host "UAC is set to prompt for consent." -ForegroundColor Green}
    default {Write-Host "Unknown UAC status." -ForegroundColor Yellow}
}

# Check 4 - Automatic Updates Status
$automaticUpdatesStatus = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update').AUOptions
switch ($automaticUpdatesStatus) {
    1 {Write-Host "Automatic updates are disabled." -ForegroundColor Red}
    2 {Write-Host "Automatic updates are set to notify for download and notify for install." -ForegroundColor Green}
    3 {Write-Host "Automatic updates are set to download and notify for install." -ForegroundColor Green}
    4 {Write-Host "Automatic updates are set to automatic download and scheduled installation." -ForegroundColor Green}
    default {Write-Host "Unknown automatic updates status." -ForegroundColor Yellow}
}

# Check 5 - BitLocker Status
$bitlockerStatus = Get-BitLockerVolume | Select-Object -ExpandProperty VolumeStatus
if ($bitlockerStatus -eq 'FullyEncrypted') {
    Write-Host "BitLocker is enabled and the system drive is fully encrypted." -ForegroundColor Green
} else {
    Write-Host "BitLocker is not enabled or the system drive is not fully encrypted." -ForegroundColor Red
}

# Check 6 - Guest Account Status
$guestAccountStatus = Get-WmiObject -Class Win32_UserAccount -Filter "Name='Guest'"
if ($guestAccountStatus.Disabled) {
    Write-Host "The Guest account is disabled." -ForegroundColor Green
} else {
    Write-Host "The Guest account is enabled." -ForegroundColor Red
}

# Check 7 - Network Sharing Status
$networkSharingStatus = Get-NetAdapterBinding | Where-Object {$_.ComponentID -eq 'ms_server'}
if ($networkSharingStatus.Enabled) {
    Write-Host "Network sharing is enabled." -ForegroundColor Red
} else {
    Write-Host "Network sharing is disabled." -ForegroundColor Green
}

# Check 8 - PowerShell Execution Policy
$executionPolicy = Get-ExecutionPolicy
if ($executionPolicy -eq 'RemoteSigned' -or $executionPolicy -eq 'AllSigned') {
    Write-Host "PowerShell execution policy is set to $executionPolicy." -ForegroundColor Green
} else {
    Write-Host "PowerShell execution policy is set to $executionPolicy, which is not secure." -ForegroundColor Red
}

# Check 9 - Secure Boot Status
$secureBootStatus = Confirm-SecureBootUEFI
if ($secureBootStatus) {
Write-Host "Secure Boot is enabled." -ForegroundColor Green
} else {
Write-Host "Secure Boot is not enabled or not supported." -ForegroundColor Red
}

# Check 10 - SMBv1 Status
$smb1Status = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
if ($smb1Status.State -eq 'Disabled') {
Write-Host "SMBv1 is disabled." -ForegroundColor Green
} else {
Write-Host "SMBv1 is enabled." -ForegroundColor Red
}

#Check 11 - RDP Status
$rdpStatus = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'
if ($rdpStatus.fDenyTSConnections -eq 1) {
Write-Host "Remote Desktop is disabled." -ForegroundColor Green
} else {
Write-Host "Remote Desktop is enabled." -ForegroundColor Red
}

# Check 12 - Local Administrator Password Solution (LAPS) Status
try {
$lapsStatus = Get-AdmPwdPassword -ComputerName $env:COMPUTERNAME -ErrorAction Stop
Write-Host "LAPS is configured and active." -ForegroundColor Green
} catch {
Write-Host "LAPS is not configured or not active." -ForegroundColor Red
}

# Check 15 - Audit Policy
$auditPolicy = AuditPol.exe /get /category:*
if ($auditPolicy -match 'Success and Failure') {
Write-Host "Audit policy is configured for Success and Failure events." -ForegroundColor Green
} else {
Write-Host "Audit policy is not optimally configured." -ForegroundColor Red
}

# Output security report
$outputFile = "SecurityReport_$(Get-Date -Format yyyyMMdd).txt"
$reportContent = @"
Security Report - $(Get-Date -Format "yyyy/MM/dd HH:mm")

Check 1: Windows Defender Status
$defenderStatus

Check 2: Firewall Status
$firewallStatus

Check 3: User Account Control (UAC) Status
$uacStatus

Check 4: Automatic Updates Status
$automaticUpdatesStatus

Check 5: BitLocker Status
$bitlockerStatus

Check 6: Guest Account Status
$guestAccountStatus

Check 7: Network Sharing Status
$networkSharingStatus

Check 8: PowerShell Execution Policy
$executionPolicy

Check 9: Secure Boot Status
$secureBootStatus

Check 10: SMBv1 Status
$smb1Status

Check 11: RDP Status
$rdpStatus

Check 12: Local Administrator Password Solution (LAPS) Status
$lapsStatus

Check 13: Account Lockout Policy
$lockoutPolicy

Check 14: Password Complexity Policy
$pwdComplexity

Check 15: Audit Policy
$auditPolicy
"@

Set-Content -Path $outputFile -Value $reportContent
Write-Host "Security report saved to $outputFile" -ForegroundColor Green

Read-Host "Press Enter to exit..."
