# Windows Security Checks & Persistence Enumeration Script
# Combines security configuration auditing with persistence mechanism enumeration

# Check for Constrained Language Mode
$script:ConstrainedMode = $ExecutionContext.SessionState.LanguageMode -eq 'ConstrainedLanguage'

if ($script:ConstrainedMode) {
    Write-Host "WARNING: PowerShell is running in Constrained Language Mode." -ForegroundColor Yellow
    Write-Host "Security configuration checks will be skipped (require custom objects)." -ForegroundColor Yellow
    Write-Host "Persistence enumeration will still run." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "CLM is typically enforced by AppLocker, WDAC, or Device Guard." -ForegroundColor Gray
    Write-Host ""
    $script:IsAdmin = $false
} else {
    # Admin check - allows non-admin execution with warnings
    $script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-NOT $script:IsAdmin) {
        Write-Host "WARNING: Running without Administrator privileges. Some checks will be skipped or may return limited information." -ForegroundColor Yellow
        Write-Host "For complete security assessment, run as Administrator.`n" -ForegroundColor Yellow
    }
}

# --- Function Definitions ---

function Test-RequiresAdmin {
    param([string]$CheckName)

    if (-NOT $script:IsAdmin) {
        return [PSCustomObject]@{
            CheckName = $CheckName
            Status    = 'Warning'
            Message   = 'This check requires Administrator privileges. Run as Administrator for full results.'
        }
    }
    return $null
}

function Get-FirewallStatus {
    try {
        $firewallProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled
        $messages = @()
        $allEnabled = $true
        foreach ($fwProfile in $firewallProfiles) {
            if ($fwProfile.Enabled) {
                $messages += "  - $($fwProfile.Name) Firewall: Enabled"
            } else {
                $messages += "  - $($fwProfile.Name) Firewall: Disabled"
                $allEnabled = $false
            }
        }

        $status = if ($allEnabled) { 'Good' } else { 'Bad' }
        $replicationCmd = if ($status -eq 'Bad') {
            "# PowerShell:`nGet-NetFirewallProfile | Select-Object Name, Enabled`n# CMD:`nnetsh advfirewall show allprofiles state"
        } else { $null }

        return [PSCustomObject]@{
            CheckName      = 'Firewall'
            Status         = $status
            Message        = "Windows Firewall Status:`n" + ($messages -join "`n")
            ReplicationCmd = $replicationCmd
        }
    } catch {
        return [PSCustomObject]@{
            CheckName      = 'Firewall'
            Status         = 'Error'
            Message        = "Could not retrieve Firewall status. Error: $($_.Exception.Message)"
            ReplicationCmd = $null
        }
    }
}

function Get-UACStatus {
    try {
        $uacValue = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -ErrorAction Stop).ConsentPromptBehaviorAdmin
        switch ($uacValue) {
            2 {
                $message = "UAC is set to 'Prompt for consent on the secure desktop'."
                $status = 'Good'
            }
            5 {
                $message = "UAC is set to 'Prompt for consent'."
                $status = 'Good'
            }
            0 {
                $message = "UAC is disabled."
                $status = 'Bad'
            }
            default {
                $message = "UAC has an unknown or non-standard setting (Value: $uacValue)."
                $status = 'Warning'
            }
        }
        $replicationCmd = if ($status -eq 'Bad') {
            "# PowerShell:`nGet-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' | Select-Object ConsentPromptBehaviorAdmin`n# CMD:`nreg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin"
        } else { $null }

        return [PSCustomObject]@{
            CheckName      = 'User Account Control (UAC)'
            Status         = $status
            Message        = $message
            ReplicationCmd = $replicationCmd
        }
    } catch {
        return [PSCustomObject]@{
            CheckName      = 'User Account Control (UAC)'
            Status         = 'Error'
            Message        = "Could not retrieve UAC status. Error: $($_.Exception.Message)"
            ReplicationCmd = $null
        }
    }
}

function Get-WindowsUpdateStatus {
    try {
        $wuService = Get-Service -Name wuauserv -ErrorAction Stop

        $messages = @()
        $issues = @()

        if ($wuService.Status -eq 'Running') {
            $messages += "Windows Update service: Running"
        } else {
            $issues += "Windows Update service is not running (Status: $($wuService.Status))"
        }

        if ($wuService.StartType -eq 'Automatic' -or $wuService.StartType -eq 'Manual') {
            $messages += "Service start type: $($wuService.StartType)"
        } else {
            $issues += "Windows Update service is disabled"
        }

        # Check for pending updates
        try {
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $searchResult = $updateSearcher.Search("IsInstalled=0")

            if ($searchResult.Updates.Count -gt 0) {
                $issues += "$($searchResult.Updates.Count) pending update(s) available"
            } else {
                $messages += "No pending updates"
            }
        } catch {
            $messages += "Could not check for pending updates"
        }

        # Check last update time via registry
        try {
            $lastSuccess = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install' -Name 'LastSuccessTime' -ErrorAction SilentlyContinue
            if ($lastSuccess) {
                $lastUpdateDate = [DateTime]::Parse($lastSuccess.LastSuccessTime)
                $daysSinceUpdate = ((Get-Date) - $lastUpdateDate).Days

                if ($daysSinceUpdate -le 7) {
                    $messages += "Last update: $daysSinceUpdate day(s) ago"
                } elseif ($daysSinceUpdate -le 30) {
                    $issues += "Last successful update was $daysSinceUpdate days ago"
                } else {
                    $issues += "Last successful update was $daysSinceUpdate days ago (critically outdated)"
                }
            }
        } catch {
            # Registry key might not exist, not critical
        }

        $status = if ($issues.Count -eq 0) { 'Good' } elseif ($issues.Count -le 1) { 'Warning' } else { 'Bad' }

        $finalMessage = if ($issues.Count -gt 0) {
            "Issues: " + ($issues -join '; ') + ". " + ($messages -join '; ')
        } else {
            ($messages -join '; ')
        }

        $replicationCmd = if ($status -eq 'Bad') {
            "# PowerShell:`nGet-Service -Name wuauserv | Select-Object Name, Status, StartType`n# CMD:`nsc query wuauserv"
        } else { $null }

        return [PSCustomObject]@{
            CheckName      = 'Windows Update'
            Status         = $status
            Message        = $finalMessage + '.'
            ReplicationCmd = $replicationCmd
        }
    } catch {
        return [PSCustomObject]@{
            CheckName      = 'Windows Update'
            Status         = 'Error'
            Message        = "Could not retrieve Windows Update status. Error: $($_.Exception.Message)"
            ReplicationCmd = $null
        }
    }
}

function Get-BitLockerStatus {
    $adminCheck = Test-RequiresAdmin -CheckName 'BitLocker'
    if ($adminCheck) { return $adminCheck }

    $replicationCmd = "# PowerShell (Admin):`nGet-BitLockerVolume -MountPoint $env:SystemDrive | Select-Object MountPoint, VolumeStatus, ProtectionStatus`n# CMD (Admin):`nmanage-bde -status $env:SystemDrive"

    try {
        $systemDrive = $env:SystemDrive
        $bitlockerVolume = Get-BitLockerVolume -MountPoint $systemDrive -ErrorAction Stop

        if ($bitlockerVolume.VolumeStatus -eq 'FullyEncrypted') {
            return [PSCustomObject]@{
                CheckName      = 'BitLocker'
                Status         = 'Good'
                Message        = "BitLocker is enabled and the system drive ($systemDrive) is fully encrypted."
                ReplicationCmd = $null
            }
        } else {
            return [PSCustomObject]@{
                CheckName      = 'BitLocker'
                Status         = 'Bad'
                Message        = "BitLocker is not fully encrypted on the system drive ($systemDrive). Status: $($bitlockerVolume.VolumeStatus)"
                ReplicationCmd = $replicationCmd
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName      = 'BitLocker'
            Status         = 'Bad'
            Message        = "BitLocker is not enabled or the system drive ($($env:SystemDrive)) is not encrypted. Error: $($_.Exception.Message)"
            ReplicationCmd = $replicationCmd
        }
    }
}

function Get-GuestAccountStatus {
    $replicationCmd = "# PowerShell:`nGet-WmiObject -Class Win32_UserAccount -Filter `"Name='Guest'`" | Select-Object Name, Disabled`n# CMD:`nnet user Guest"

    try {
        $guestAccount = Get-WmiObject -Class Win32_UserAccount -Filter "Name='Guest'" -ErrorAction Stop
        if ($guestAccount.Disabled) {
            return [PSCustomObject]@{
                CheckName      = 'Guest Account'
                Status         = 'Good'
                Message        = 'The Guest account is disabled.'
                ReplicationCmd = $null
            }
        } else {
            return [PSCustomObject]@{
                CheckName      = 'Guest Account'
                Status         = 'Bad'
                Message        = 'The Guest account is enabled.'
                ReplicationCmd = $replicationCmd
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName      = 'Guest Account'
            Status         = 'Error'
            Message        = "Could not retrieve Guest Account status. Error: $($_.Exception.Message)"
            ReplicationCmd = $null
        }
    }
}

function Get-NetworkSharingStatus {
    $replicationCmd = "# PowerShell:`nGet-NetAdapterBinding | Where-Object { `$_.ComponentID -eq 'ms_server' } | Select-Object Name, DisplayName, Enabled"

    try {
        $bindings = Get-NetAdapterBinding | Where-Object { $_.ComponentID -eq 'ms_server' -and $_.Enabled }
        if ($bindings) {
            $adapters = ($bindings | ForEach-Object { $_.Name }) -join ', '
            return [PSCustomObject]@{
                CheckName      = 'Network Sharing'
                Status         = 'Bad'
                Message        = "Network sharing (File and Printer Sharing) is enabled on: $adapters"
                ReplicationCmd = $replicationCmd
            }
        } else {
            return [PSCustomObject]@{
                CheckName      = 'Network Sharing'
                Status         = 'Good'
                Message        = 'Network sharing (File and Printer Sharing) is disabled on all network adapters.'
                ReplicationCmd = $null
            }
        }
    } catch {
        if (-NOT $script:IsAdmin) {
            return [PSCustomObject]@{
                CheckName      = 'Network Sharing'
                Status         = 'Warning'
                Message        = 'Could not retrieve Network Sharing status. Administrator privileges may be required.'
                ReplicationCmd = $null
            }
        }
        return [PSCustomObject]@{
            CheckName      = 'Network Sharing'
            Status         = 'Error'
            Message        = "Could not retrieve Network Sharing status. Error: $($_.Exception.Message)"
            ReplicationCmd = $null
        }
    }
}

function Get-ExecutionPolicyStatus {
    $replicationCmd = "# PowerShell:`nGet-ExecutionPolicy -List`n# CMD:`npowershell -Command `"Get-ExecutionPolicy`""

    try {
        $policy = Get-ExecutionPolicy
        if ($policy -in @('Restricted', 'AllSigned', 'RemoteSigned')) {
            return [PSCustomObject]@{
                CheckName      = 'PowerShell Execution Policy'
                Status         = 'Good'
                Message        = "PowerShell execution policy is set to '$policy'."
                ReplicationCmd = $null
            }
        } else {
            return [PSCustomObject]@{
                CheckName      = 'PowerShell Execution Policy'
                Status         = 'Bad'
                Message        = "PowerShell execution policy is set to '$policy', which is not secure."
                ReplicationCmd = $replicationCmd
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName      = 'PowerShell Execution Policy'
            Status         = 'Error'
            Message        = "Could not retrieve PowerShell Execution Policy. Error: $($_.Exception.Message)"
            ReplicationCmd = $null
        }
    }
}

function Get-SecureBootStatus {
    $replicationCmd = "# PowerShell:`nConfirm-SecureBootUEFI`n# Alternative:`nreg query HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State /v UEFISecureBootEnabled"

    try {
        try {
            $isSecureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
            if ($isSecureBoot) {
                return [PSCustomObject]@{
                    CheckName      = 'Secure Boot'
                    Status         = 'Good'
                    Message        = 'Secure Boot is enabled.'
                    ReplicationCmd = $null
                }
            } else {
                return [PSCustomObject]@{
                    CheckName      = 'Secure Boot'
                    Status         = 'Bad'
                    Message        = 'Secure Boot is disabled.'
                    ReplicationCmd = $replicationCmd
                }
            }
        } catch {
            try {
                $secureBootEnabled = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name 'UEFISecureBootEnabled' -ErrorAction Stop).UEFISecureBootEnabled
                if ($secureBootEnabled -eq 1) {
                    return [PSCustomObject]@{
                        CheckName      = 'Secure Boot'
                        Status         = 'Good'
                        Message        = 'Secure Boot is enabled.'
                        ReplicationCmd = $null
                    }
                } else {
                    return [PSCustomObject]@{
                        CheckName      = 'Secure Boot'
                        Status         = 'Bad'
                        Message        = 'Secure Boot is disabled.'
                        ReplicationCmd = $replicationCmd
                    }
                }
            } catch {
                return [PSCustomObject]@{
                    CheckName      = 'Secure Boot'
                    Status         = 'Warning'
                    Message        = 'Could not determine Secure Boot status. System may not support UEFI Secure Boot (Legacy BIOS mode).'
                    ReplicationCmd = $null
                }
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName      = 'Secure Boot'
            Status         = 'Warning'
            Message        = "Could not determine Secure Boot status. Error: $($_.Exception.Message)"
            ReplicationCmd = $null
        }
    }
}

function Get-SMBv1Status {
    $adminCheck = Test-RequiresAdmin -CheckName 'SMBv1'
    if ($adminCheck) { return $adminCheck }

    $replicationCmd = "# PowerShell (Admin):`nGet-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object FeatureName, State`n# Alternative:`nGet-SmbServerConfiguration | Select-Object EnableSMB1Protocol"

    try {
        $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        if ($smb1Feature.State -eq 'Disabled') {
            return [PSCustomObject]@{
                CheckName      = 'SMBv1'
                Status         = 'Good'
                Message        = 'SMBv1 is disabled.'
                ReplicationCmd = $null
            }
        } else {
            return [PSCustomObject]@{
                CheckName      = 'SMBv1'
                Status         = 'Bad'
                Message        = "SMBv1 is enabled (State: $($smb1Feature.State))."
                ReplicationCmd = $replicationCmd
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName      = 'SMBv1'
            Status         = 'Error'
            Message        = "Could not retrieve SMBv1 status. Error: $($_.Exception.Message)"
            ReplicationCmd = $null
        }
    }
}

function Get-AuditPolicyStatus {
    $adminCheck = Test-RequiresAdmin -CheckName 'Audit Policy (Logon/Logoff)'
    if ($adminCheck) { return $adminCheck }

    $replicationCmd = "# CMD (Admin):`nauditpol /get /category:`"Logon/Logoff`""

    try {
        $auditPolicy = auditpol.exe /get /category:"Logon/Logoff"
        if ($auditPolicy -match 'Success and Failure') {
            return [PSCustomObject]@{
                CheckName      = 'Audit Policy (Logon/Logoff)'
                Status         = 'Good'
                Message        = 'Audit policy for Logon/Logoff is configured for "Success and Failure".'
                ReplicationCmd = $null
            }
        } elseif ($auditPolicy -match 'Success' -or $auditPolicy -match 'Failure') {
            return [PSCustomObject]@{
                CheckName      = 'Audit Policy (Logon/Logoff)'
                Status         = 'Warning'
                Message        = 'Audit policy for Logon/Logoff is not configured for both Success and Failure.'
                ReplicationCmd = $null
            }
        } else {
            return [PSCustomObject]@{
                CheckName      = 'Audit Policy (Logon/Logoff)'
                Status         = 'Bad'
                Message        = 'Audit policy for Logon/Logoff is not configured.'
                ReplicationCmd = $replicationCmd
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName      = 'Audit Policy (Logon/Logoff)'
            Status         = 'Error'
            Message        = "Could not retrieve Audit Policy status. Error: $($_.Exception.Message)"
            ReplicationCmd = $null
        }
    }
}

function Get-VBSStatus {
    $replicationCmd = "# PowerShell:`nGet-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object VirtualizationBasedSecurityStatus, CodeIntegrityPolicyEnforcementStatus`n# CMD:`nmsinfo32 /report vbs.txt && findstr /i `"Virtualization`" vbs.txt"

    try {
        $vbs = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop

        if ($null -eq $vbs) {
            return [PSCustomObject]@{
                CheckName      = 'Virtualization-Based Security (VBS)'
                Status         = 'Warning'
                Message        = 'VBS information not available. This feature requires Windows 10/11 Enterprise or Pro.'
                ReplicationCmd = $null
            }
        }

        $vbsRunning = $vbs.VirtualizationBasedSecurityStatus -eq 2
        $hvciRunning = $vbs.CodeIntegrityPolicyEnforcementStatus -eq 2

        $messages = @()
        $overallStatus = 'Good'

        if ($vbsRunning) {
            $messages += "VBS is enabled and running"
        } else {
            $messages += "VBS is not running"
            $overallStatus = 'Bad'
        }

        if ($hvciRunning) {
            $messages += "Memory Integrity (HVCI) is enabled and running"
        } else {
            $messages += "Memory Integrity (HVCI) is not enabled"
            if ($overallStatus -eq 'Good') { $overallStatus = 'Warning' }
        }

        return [PSCustomObject]@{
            CheckName      = 'Virtualization-Based Security (VBS)'
            Status         = $overallStatus
            Message        = ($messages -join '. ') + '.'
            ReplicationCmd = if ($overallStatus -eq 'Bad') { $replicationCmd } else { $null }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName      = 'Virtualization-Based Security (VBS)'
            Status         = 'Warning'
            Message        = "Could not retrieve VBS status. Error: $($_.Exception.Message)"
            ReplicationCmd = $null
        }
    }
}

function Get-CredentialGuardStatus {
    # Credential Guard only returns Warning status, not Bad - no replication command needed
    try {
        $cg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop

        if ($null -eq $cg) {
            return [PSCustomObject]@{
                CheckName      = 'Credential Guard'
                Status         = 'Warning'
                Message        = 'Credential Guard information not available.'
                ReplicationCmd = $null
            }
        }

        if ($cg.SecurityServicesRunning -contains 1) {
            return [PSCustomObject]@{
                CheckName      = 'Credential Guard'
                Status         = 'Good'
                Message        = 'Credential Guard is enabled and running.'
                ReplicationCmd = $null
            }
        } elseif ($cg.SecurityServicesConfigured -contains 1) {
            return [PSCustomObject]@{
                CheckName      = 'Credential Guard'
                Status         = 'Warning'
                Message        = 'Credential Guard is configured but not currently running.'
                ReplicationCmd = $null
            }
        } else {
            return [PSCustomObject]@{
                CheckName      = 'Credential Guard'
                Status         = 'Warning'
                Message        = 'Credential Guard is not enabled (default on Windows 11 22H2+).'
                ReplicationCmd = $null
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName      = 'Credential Guard'
            Status         = 'Warning'
            Message        = "Could not retrieve Credential Guard status. Error: $($_.Exception.Message)"
            ReplicationCmd = $null
        }
    }
}

function Get-TPMStatus {
    $adminCheck = Test-RequiresAdmin -CheckName 'TPM 2.0'
    if ($adminCheck) { return $adminCheck }

    $replicationCmd = "# PowerShell (Admin):`nGet-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled`n# CMD:`ntpm.msc"

    try {
        $tpm = Get-Tpm -ErrorAction Stop

        $messages = @()
        $status = 'Good'

        if (-not $tpm.TpmPresent) {
            return [PSCustomObject]@{
                CheckName      = 'TPM 2.0'
                Status         = 'Bad'
                Message        = 'TPM is not present on this system. TPM 2.0 is required for Windows 11.'
                ReplicationCmd = $replicationCmd
            }
        }

        if (-not $tpm.TpmReady) {
            $messages += "TPM is present but not ready"
            $status = 'Warning'
        } else {
            $messages += "TPM is present and ready"
        }

        if (-not $tpm.TpmEnabled) {
            $messages += "TPM is not enabled"
            $status = 'Bad'
        }

        try {
            $tpmVersion = (Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction Stop).SpecVersion
            if ($tpmVersion -like "2.*") {
                $messages += "TPM version 2.0 detected"
            } elseif ($tpmVersion -like "1.*") {
                $messages += "TPM version 1.2 detected (2.0 required for Windows 11)"
                $status = 'Warning'
            } else {
                $messages += "TPM version: $tpmVersion"
            }
        } catch {
            $messages += "TPM version could not be determined"
        }

        return [PSCustomObject]@{
            CheckName      = 'TPM 2.0'
            Status         = $status
            Message        = ($messages -join '. ') + '.'
            ReplicationCmd = if ($status -eq 'Bad') { $replicationCmd } else { $null }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName      = 'TPM 2.0'
            Status         = 'Error'
            Message        = "Could not retrieve TPM status. Error: $($_.Exception.Message)"
            ReplicationCmd = $null
        }
    }
}

function Get-ASRStatus {
    $replicationCmd = "# PowerShell:`nGet-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions"

    try {
        $mpPref = Get-MpPreference -ErrorAction Stop

        if ($null -eq $mpPref.AttackSurfaceReductionRules_Ids -or $mpPref.AttackSurfaceReductionRules_Ids.Count -eq 0) {
            return [PSCustomObject]@{
                CheckName      = 'Attack Surface Reduction (ASR) Rules'
                Status         = 'Warning'
                Message        = 'No ASR rules are configured. ASR rules help prevent Office exploits, script-based attacks, and credential theft.'
                ReplicationCmd = $null
            }
        }

        $enabledCount = ($mpPref.AttackSurfaceReductionRules_Actions | Where-Object { $_ -eq 1 }).Count
        $auditCount = ($mpPref.AttackSurfaceReductionRules_Actions | Where-Object { $_ -eq 2 }).Count
        $totalRules = $mpPref.AttackSurfaceReductionRules_Ids.Count

        $message = "$enabledCount ASR rule(s) enabled, $auditCount in audit mode out of $totalRules configured"

        $status = if ($enabledCount -ge 5) { 'Good' } elseif ($enabledCount -gt 0) { 'Warning' } else { 'Bad' }

        return [PSCustomObject]@{
            CheckName      = 'Attack Surface Reduction (ASR) Rules'
            Status         = $status
            Message        = $message + '.'
            ReplicationCmd = if ($status -eq 'Bad') { $replicationCmd } else { $null }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName      = 'Attack Surface Reduction (ASR) Rules'
            Status         = 'Error'
            Message        = "Could not retrieve ASR status. Error: $($_.Exception.Message)"
            ReplicationCmd = $null
        }
    }
}

function Get-ControlledFolderAccessStatus {
    # Only returns Warning status, not Bad - no replication command needed
    try {
        $mpPref = Get-MpPreference -ErrorAction Stop

        switch ($mpPref.EnableControlledFolderAccess) {
            1 {
                return [PSCustomObject]@{
                    CheckName      = 'Controlled Folder Access (Anti-Ransomware)'
                    Status         = 'Good'
                    Message        = 'Controlled Folder Access is enabled, providing ransomware protection.'
                    ReplicationCmd = $null
                }
            }
            2 {
                return [PSCustomObject]@{
                    CheckName      = 'Controlled Folder Access (Anti-Ransomware)'
                    Status         = 'Warning'
                    Message        = 'Controlled Folder Access is in audit mode only.'
                    ReplicationCmd = $null
                }
            }
            default {
                return [PSCustomObject]@{
                    CheckName      = 'Controlled Folder Access (Anti-Ransomware)'
                    Status         = 'Warning'
                    Message        = 'Controlled Folder Access is disabled. This provides ransomware protection for user folders.'
                    ReplicationCmd = $null
                }
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName      = 'Controlled Folder Access (Anti-Ransomware)'
            Status         = 'Error'
            Message        = "Could not retrieve Controlled Folder Access status. Error: $($_.Exception.Message)"
            ReplicationCmd = $null
        }
    }
}

function Get-EnhancedDefenderStatus {
    $replicationCmd = "# PowerShell:`nGet-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusSignatureLastUpdated`nGet-MpPreference | Select-Object MAPSReporting, EnableNetworkProtection, PUAProtection"

    try {
        $mpPref = Get-MpPreference -ErrorAction Stop
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop

        $messages = @()
        $issues = @()

        if ($mpStatus.RealTimeProtectionEnabled) {
            $messages += "Real-time protection: Enabled"
        } else {
            $issues += "Real-time protection is disabled"
        }

        if ($mpPref.MAPSReporting -gt 0) {
            $messages += "Cloud protection: Enabled"
        } else {
            $issues += "Cloud protection is disabled"
        }

        if ($mpPref.EnableNetworkProtection -eq 1) {
            $messages += "Network protection: Enabled"
        } elseif ($mpPref.EnableNetworkProtection -eq 2) {
            $messages += "Network protection: Audit mode"
        } else {
            $issues += "Network protection is disabled"
        }

        try {
            $tamperProtection = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name 'TamperProtection' -ErrorAction SilentlyContinue).TamperProtection
            if ($tamperProtection -eq 5 -or $tamperProtection -eq 1) {
                $messages += "Tamper protection: Enabled"
            } elseif ($tamperProtection -eq 0) {
                $issues += "Tamper protection is disabled"
            } else {
                $messages += "Tamper protection: Status unknown (value: $tamperProtection)"
            }
        } catch {
            $messages += "Tamper protection: Status unknown"
        }

        if ($mpPref.PUAProtection -eq 1) {
            $messages += "PUA protection: Enabled"
        } else {
            $issues += "PUA (Potentially Unwanted Application) protection is disabled"
        }

        $sigAge = (Get-Date) - $mpStatus.AntivirusSignatureLastUpdated
        if ($sigAge.Days -eq 0) {
            $messages += "Signatures: Up to date (today)"
        } elseif ($sigAge.Days -le 2) {
            $messages += "Signatures: $($sigAge.Days) day(s) old"
        } else {
            $issues += "Signatures are $($sigAge.Days) days old"
        }

        $status = if ($issues.Count -eq 0) { 'Good' } elseif ($issues.Count -le 2) { 'Warning' } else { 'Bad' }

        $finalMessage = if ($issues.Count -gt 0) {
            "Issues: " + ($issues -join '; ') + ". " + ($messages -join '; ')
        } else {
            ($messages -join '; ')
        }

        return [PSCustomObject]@{
            CheckName      = 'Windows Defender (Enhanced)'
            Status         = $status
            Message        = $finalMessage + '.'
            ReplicationCmd = if ($status -eq 'Bad') { $replicationCmd } else { $null }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName      = 'Windows Defender (Enhanced)'
            Status         = 'Error'
            Message        = "Could not retrieve enhanced Defender status. Error: $($_.Exception.Message)"
            ReplicationCmd = $null
        }
    }
}

function Get-DefenderExclusionsStatus {
    $replicationCmd = "# PowerShell (Admin):`nGet-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess, ExclusionIpAddress"

    try {
        $mpPref = Get-MpPreference -ErrorAction Stop

        if ($mpPref.ExclusionPath -and $mpPref.ExclusionPath[0] -like "*Must be an administrator*") {
            return [PSCustomObject]@{
                CheckName      = 'Windows Defender Exclusions'
                Status         = 'Warning'
                Message        = 'Cannot view exclusions. Administrator privileges required to view detailed exclusion list.'
                ReplicationCmd = $null
            }
        }

        $exclusionDetails = @()
        $totalExclusions = 0

        if ($mpPref.ExclusionPath -and $mpPref.ExclusionPath.Count -gt 0) {
            $paths = $mpPref.ExclusionPath -join ', '
            $exclusionDetails += "Paths ($($mpPref.ExclusionPath.Count)): $paths"
            $totalExclusions += $mpPref.ExclusionPath.Count
        }

        if ($mpPref.ExclusionExtension -and $mpPref.ExclusionExtension.Count -gt 0) {
            $extensions = $mpPref.ExclusionExtension -join ', '
            $exclusionDetails += "Extensions ($($mpPref.ExclusionExtension.Count)): $extensions"
            $totalExclusions += $mpPref.ExclusionExtension.Count
        }

        if ($mpPref.ExclusionProcess -and $mpPref.ExclusionProcess.Count -gt 0) {
            $processes = $mpPref.ExclusionProcess -join ', '
            $exclusionDetails += "Processes ($($mpPref.ExclusionProcess.Count)): $processes"
            $totalExclusions += $mpPref.ExclusionProcess.Count
        }

        if ($mpPref.ExclusionIpAddress -and $mpPref.ExclusionIpAddress.Count -gt 0) {
            $ips = $mpPref.ExclusionIpAddress -join ', '
            $exclusionDetails += "IP Addresses ($($mpPref.ExclusionIpAddress.Count)): $ips"
            $totalExclusions += $mpPref.ExclusionIpAddress.Count
        }

        if ($totalExclusions -eq 0) {
            return [PSCustomObject]@{
                CheckName      = 'Windows Defender Exclusions'
                Status         = 'Good'
                Message        = 'No exclusions configured. All files and processes are scanned.'
                ReplicationCmd = $null
            }
        } elseif ($totalExclusions -le 5) {
            return [PSCustomObject]@{
                CheckName      = 'Windows Defender Exclusions'
                Status         = 'Warning'
                Message        = "$totalExclusions exclusion(s) configured. " + ($exclusionDetails -join ' | ') + '. Review to ensure necessary.'
                ReplicationCmd = $null
            }
        } else {
            return [PSCustomObject]@{
                CheckName      = 'Windows Defender Exclusions'
                Status         = 'Bad'
                Message        = "$totalExclusions exclusion(s) configured. " + ($exclusionDetails -join ' | ') + '. Excessive exclusions reduce protection.'
                ReplicationCmd = $replicationCmd
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName      = 'Windows Defender Exclusions'
            Status         = 'Error'
            Message        = "Could not retrieve Windows Defender exclusions. Error: $($_.Exception.Message)"
            ReplicationCmd = $null
        }
    }
}

function Get-WindowsHelloStatus {
    # Only returns Warning status, not Bad - no replication command needed
    try {
        $helloConfigured = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\Credential Provider\{8AF662BF-65A0-4D0A-A540-A338A999D36F}"

        if ($helloConfigured) {
            return [PSCustomObject]@{
                CheckName      = 'Windows Hello for Business'
                Status         = 'Good'
                Message        = 'Windows Hello appears to be configured on this device.'
                ReplicationCmd = $null
            }
        } else {
            return [PSCustomObject]@{
                CheckName      = 'Windows Hello for Business'
                Status         = 'Warning'
                Message        = 'Windows Hello does not appear to be configured. Windows Hello is required for Personal Data Encryption.'
                ReplicationCmd = $null
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName      = 'Windows Hello for Business'
            Status         = 'Warning'
            Message        = "Could not determine Windows Hello status. Error: $($_.Exception.Message)"
            ReplicationCmd = $null
        }
    }
}

function Get-ModernLAPSStatus {
    # Only returns Warning status, not Bad - no replication command needed
    try {
        $modernLaps = Get-Command Get-LapsADPassword -ErrorAction SilentlyContinue

        if ($modernLaps) {
            try {
                $lapsConfig = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config' -ErrorAction SilentlyContinue
                if ($lapsConfig) {
                    return [PSCustomObject]@{
                        CheckName      = 'Windows LAPS'
                        Status         = 'Good'
                        Message        = 'Windows LAPS (modern built-in) is configured.'
                        ReplicationCmd = $null
                    }
                } else {
                    return [PSCustomObject]@{
                        CheckName      = 'Windows LAPS'
                        Status         = 'Warning'
                        Message        = 'Windows LAPS cmdlets available but configuration not detected.'
                        ReplicationCmd = $null
                    }
                }
            } catch {
                return [PSCustomObject]@{
                    CheckName      = 'Windows LAPS'
                    Status         = 'Warning'
                    Message        = 'Windows LAPS cmdlets available but status unclear.'
                    ReplicationCmd = $null
                }
            }
        }

        if (Get-Module -ListAvailable -Name AdmPwd.PS) {
            return [PSCustomObject]@{
                CheckName      = 'Windows LAPS'
                Status         = 'Warning'
                Message        = 'Legacy LAPS (AdmPwd.PS) detected. Consider upgrading to Windows LAPS.'
                ReplicationCmd = $null
            }
        }

        return [PSCustomObject]@{
            CheckName      = 'Windows LAPS'
            Status         = 'Warning'
            Message        = 'LAPS is not installed. Windows LAPS is built into Windows 11 and Server 2025.'
            ReplicationCmd = $null
        }
    } catch {
        return [PSCustomObject]@{
            CheckName      = 'Windows LAPS'
            Status         = 'Warning'
            Message        = "Could not retrieve Windows LAPS status. Error: $($_.Exception.Message)"
            ReplicationCmd = $null
        }
    }
}

function Get-EnhancedRDPStatus {
    $replicationCmd = "# PowerShell:`nGet-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'`nGet-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' | Select-Object UserAuthentication, SecurityLayer, PortNumber`n# CMD:`nreg query `"HKLM\System\CurrentControlSet\Control\Terminal Server`" /v fDenyTSConnections"

    try {
        $rdpValue = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction Stop).fDenyTSConnections

        if ($rdpValue -eq 1) {
            return [PSCustomObject]@{
                CheckName      = 'Remote Desktop (RDP)'
                Status         = 'Good'
                Message        = 'Remote Desktop is disabled.'
                ReplicationCmd = $null
            }
        }

        $messages = @("RDP is enabled")
        $issues = @()

        try {
            $nlaEnabled = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction Stop).UserAuthentication
            if ($nlaEnabled -eq 1) {
                $messages += "NLA enabled"
            } else {
                $issues += "NLA (Network Level Authentication) is disabled"
            }
        } catch {
            $issues += "Could not determine NLA status"
        }

        try {
            $secLayer = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -ErrorAction Stop).SecurityLayer
            if ($secLayer -eq 2) {
                $messages += "SSL/TLS encryption"
            } elseif ($secLayer -eq 1) {
                $issues += "Security layer set to 'Negotiate' instead of SSL/TLS"
            } else {
                $issues += "Security layer is set to RDP (weak)"
            }
        } catch {
            $issues += "Could not determine security layer"
        }

        try {
            $port = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'PortNumber' -ErrorAction Stop).PortNumber
            if ($port -eq 3389) {
                $issues += "Using default port 3389 (consider changing)"
            } else {
                $messages += "Custom port: $port"
            }
        } catch {
            # Port check failed, not critical
        }

        $status = if ($issues.Count -eq 0) { 'Warning' } else { 'Bad' }
        $finalMessage = ($messages -join ', ') + '. ' + ($issues -join '. ')

        return [PSCustomObject]@{
            CheckName      = 'Remote Desktop (RDP)'
            Status         = $status
            Message        = $finalMessage.TrimEnd() + '.'
            ReplicationCmd = if ($status -eq 'Bad') { $replicationCmd } else { $null }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName      = 'Remote Desktop (RDP)'
            Status         = 'Error'
            Message        = "Could not retrieve RDP status. Error: $($_.Exception.Message)"
            ReplicationCmd = $null
        }
    }
}

function Get-SMBSigningStatus {
    $adminCheck = Test-RequiresAdmin -CheckName 'SMB Signing & Encryption'
    if ($adminCheck) { return $adminCheck }

    $replicationCmd = "# PowerShell (Admin):`nGet-SmbClientConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature`nGet-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature, EncryptData"

    try {
        $clientConfig = Get-SmbClientConfiguration -ErrorAction Stop
        $serverConfig = Get-SmbServerConfiguration -ErrorAction Stop

        $messages = @()
        $issues = @()

        if ($clientConfig.RequireSecuritySignature) {
            $messages += "SMB client signing: Required"
        } elseif ($clientConfig.EnableSecuritySignature) {
            $issues += "SMB client signing is enabled but not required"
        } else {
            $issues += "SMB client signing is disabled"
        }

        if ($serverConfig.RequireSecuritySignature) {
            $messages += "SMB server signing: Required"
        } elseif ($serverConfig.EnableSecuritySignature) {
            $issues += "SMB server signing is enabled but not required"
        } else {
            $issues += "SMB server signing is disabled"
        }

        if ($serverConfig.EncryptData) {
            $messages += "SMB encryption: Enabled"
        } else {
            $issues += "SMB encryption is not required"
        }

        $status = if ($issues.Count -eq 0) { 'Good' } elseif ($issues.Count -le 1) { 'Warning' } else { 'Bad' }

        $finalMessage = if ($issues.Count -gt 0) {
            "Issues: " + ($issues -join '; ') + ". " + ($messages -join '; ')
        } else {
            ($messages -join '; ')
        }

        return [PSCustomObject]@{
            CheckName      = 'SMB Signing & Encryption'
            Status         = $status
            Message        = $finalMessage + '.'
            ReplicationCmd = if ($status -eq 'Bad') { $replicationCmd } else { $null }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName      = 'SMB Signing & Encryption'
            Status         = 'Error'
            Message        = "Could not retrieve SMB signing status. Error: $($_.Exception.Message)"
            ReplicationCmd = $null
        }
    }
}

function Get-IPv6Status {
    $replicationCmd = "# PowerShell:`nGet-NetAdapterBinding -ComponentID ms_tcpip6 | Select-Object Name, Enabled`n# Registry:`nreg query HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters /v DisabledComponents"

    try {
        # Check registry for IPv6 disabled components
        $ipv6Disabled = $false
        try {
            $disabledComponents = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents' -ErrorAction SilentlyContinue).DisabledComponents
            # 0xFF (255) = IPv6 disabled on all interfaces
            # 0x20 (32) = Prefer IPv4 over IPv6
            # 0x00 or not set = IPv6 enabled (default)
            if ($disabledComponents -eq 0xFF) {
                $ipv6Disabled = $true
            }
        } catch {
            # Key doesn't exist, IPv6 is enabled by default
        }

        # Check adapter bindings
        $adaptersWithIPv6 = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop | Where-Object { $_.Enabled -eq $true }
        $adaptersWithoutIPv6 = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop | Where-Object { $_.Enabled -eq $false }

        if ($ipv6Disabled) {
            return [PSCustomObject]@{
                CheckName      = 'IPv6 Configuration'
                Status         = 'Good'
                Message        = 'IPv6 is disabled system-wide via registry.'
                ReplicationCmd = $null
            }
        }

        if ($adaptersWithIPv6.Count -eq 0) {
            return [PSCustomObject]@{
                CheckName      = 'IPv6 Configuration'
                Status         = 'Good'
                Message        = 'IPv6 is disabled on all network adapters.'
                ReplicationCmd = $null
            }
        }

        # IPv6 is enabled - check if it appears configured
        $enabledAdapters = ($adaptersWithIPv6 | ForEach-Object { $_.Name }) -join ', '

        return [PSCustomObject]@{
            CheckName      = 'IPv6 Configuration'
            Status         = 'Bad'
            Message        = "IPv6 is enabled on: $enabledAdapters. If not required, disable to reduce attack surface."
            ReplicationCmd = $replicationCmd
        }
    } catch {
        return [PSCustomObject]@{
            CheckName      = 'IPv6 Configuration'
            Status         = 'Error'
            Message        = "Could not retrieve IPv6 status. Error: $($_.Exception.Message)"
            ReplicationCmd = $null
        }
    }
}


# ============================================================================
# MAIN SCRIPT
# ============================================================================

Write-Host "===================================" -ForegroundColor Cyan
Write-Host "Windows Security Checks" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan
Write-Host ""

# --- SECTION 1: SECURITY CONFIGURATION AUDIT ---

if ($script:ConstrainedMode) {
    Write-Host "--- Security Configuration Checks: SKIPPED (Constrained Language Mode) ---" -ForegroundColor Yellow
    Write-Host ""
    $results = @()
} else {
    Write-Host "Running Security Configuration Checks..." -ForegroundColor Cyan
    Write-Host ""

    $results = @()

    # Core Windows 11 Security Features
    $results += Get-VBSStatus
    $results += Get-CredentialGuardStatus
    $results += Get-TPMStatus
    $results += Get-SecureBootStatus

    # Windows Defender - Enhanced Checks
    $results += Get-EnhancedDefenderStatus
    $results += Get-ASRStatus
    $results += Get-ControlledFolderAccessStatus
    $results += Get-DefenderExclusionsStatus

    # Traditional Security Checks
    $results += Get-FirewallStatus
    $results += Get-UACStatus
    $results += Get-WindowsUpdateStatus
    $results += Get-BitLockerStatus

    # Authentication & Access Control
    $results += Get-WindowsHelloStatus
    $results += Get-GuestAccountStatus
    $results += Get-ModernLAPSStatus

    # Network Security
    $results += Get-EnhancedRDPStatus
    $results += Get-SMBv1Status
    $results += Get-SMBSigningStatus
    $results += Get-NetworkSharingStatus
    $results += Get-IPv6Status

    # System Configuration
    $results += Get-ExecutionPolicyStatus
    $results += Get-AuditPolicyStatus

    # Display Security Check Results
    Write-Host "--- Security Configuration Results ---" -ForegroundColor Cyan
    Write-Host ""

    foreach ($result in $results) {
        $statusColor = switch ($result.Status) {
            'Good'    { 'Green' }
            'Bad'     { 'Red' }
            'Warning' { 'Yellow' }
            'Error'   { 'Magenta' }
        }
        Write-Host "[$($result.Status.ToUpper())]" -ForegroundColor $statusColor -NoNewline
        Write-Host " $($result.CheckName): $($result.Message)"

        # Display replication command for Bad status
        if ($result.Status -eq 'Bad' -and $result.ReplicationCmd) {
            Write-Host "  [Replication Commands]" -ForegroundColor DarkGray
            $result.ReplicationCmd -split "`n" | ForEach-Object {
                Write-Host "    $_" -ForegroundColor DarkCyan
            }
            Write-Host ""
        }
    }

    Write-Host ""
}

# --- SECTION 2: PERSISTENCE ENUMERATION ---

Write-Host "===================================" -ForegroundColor Cyan
Write-Host "Persistence Enumeration" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan
Write-Host ""

# Stored Credentials
Write-Host "[+] Checking stored credentials..." -ForegroundColor Yellow
Write-Host ""
cmdkey /list
Write-Host ""

# Registry Run Keys
Write-Host "[+] Registry Run Keys (HKLM)..." -ForegroundColor Yellow
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Format-List
Write-Host ""

Write-Host "[+] Registry Run Keys (HKCU)..." -ForegroundColor Yellow
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Format-List
Write-Host ""

# Registry RunOnce Keys
Write-Host "[+] Registry RunOnce Keys (HKLM)..." -ForegroundColor Yellow
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue | Format-List
Write-Host ""

Write-Host "[+] Registry RunOnce Keys (HKCU)..." -ForegroundColor Yellow
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue | Format-List
Write-Host ""

# Startup Folders
Write-Host "[+] Startup Folder Contents (User)..." -ForegroundColor Yellow
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Select-Object Name, FullName
Write-Host ""

Write-Host "[+] Startup Folder Contents (All Users)..." -ForegroundColor Yellow
Get-ChildItem "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Select-Object Name, FullName
Write-Host ""

# Scheduled Tasks
Write-Host "[+] Scheduled Tasks (Running as current user or SYSTEM)..." -ForegroundColor Yellow
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Select-Object TaskName, TaskPath, State, @{Name="User";Expression={$_.Principal.UserId}} | Format-Table -AutoSize
Write-Host ""

# Services
Write-Host "[+] Services set to Auto-start..." -ForegroundColor Yellow
Get-Service | Where-Object {$_.StartType -eq "Automatic"} | Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize
Write-Host ""

# Winlogon Keys
Write-Host "[+] Winlogon Registry Keys..." -ForegroundColor Yellow
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue | Format-List
Write-Host ""

# Boot Execute
Write-Host "[+] Boot Execute..." -ForegroundColor Yellow
$bootExec = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name BootExecute -ErrorAction SilentlyContinue
if ($bootExec) {
    $bootExecValue = $bootExec.BootExecute -join ', '
    if ($bootExecValue -eq "autocheck autochk *") {
        Write-Host "  $bootExecValue (Default - OK)" -ForegroundColor Green
    } else {
        Write-Host "  $bootExecValue (Non-default - Review!)" -ForegroundColor Red
    }
}
Write-Host ""

# Additional persistence locations
Write-Host "[+] Image File Execution Options (potential hijacking)..." -ForegroundColor Yellow
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue | ForEach-Object {
    $debugger = Get-ItemProperty -Path $_.PSPath -Name Debugger -ErrorAction SilentlyContinue
    if ($debugger) {
        Write-Host "$($_.PSChildName): $($debugger.Debugger)" -ForegroundColor Red
    }
}
Write-Host ""

# AppInit_DLLs
Write-Host "[+] AppInit_DLLs..." -ForegroundColor Yellow
$appInit64 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name AppInit_DLLs -ErrorAction SilentlyContinue
$appInit32 = Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" -Name AppInit_DLLs -ErrorAction SilentlyContinue
if ($appInit64 -and $appInit64.AppInit_DLLs) {
    Write-Host "  x64: $($appInit64.AppInit_DLLs)" -ForegroundColor $(if ($appInit64.AppInit_DLLs -eq '') { 'Green' } else { 'Red' })
} else {
    Write-Host "  x64: (empty)" -ForegroundColor Green
}
if ($appInit32 -and $appInit32.AppInit_DLLs) {
    Write-Host "  x86: $($appInit32.AppInit_DLLs)" -ForegroundColor $(if ($appInit32.AppInit_DLLs -eq '') { 'Green' } else { 'Red' })
} else {
    Write-Host "  x86: (empty)" -ForegroundColor Green
}
Write-Host ""

# LSA Packages
Write-Host "[+] LSA Authentication Packages..." -ForegroundColor Yellow
$authPkgs = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Authentication Packages" -ErrorAction SilentlyContinue
$secPkgs = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Security Packages" -ErrorAction SilentlyContinue
if ($authPkgs) {
    Write-Host "  Authentication Packages: $($authPkgs.'Authentication Packages' -join ', ')" -ForegroundColor White
}
if ($secPkgs) {
    Write-Host "  Security Packages: $($secPkgs.'Security Packages' -join ', ')" -ForegroundColor White
}
Write-Host ""

# Credential Manager entries
Write-Host "[+] Windows Credential Manager entries..." -ForegroundColor Yellow
try {
    $credentials = cmdkey /list | Select-String "Target:" | ForEach-Object { $_.ToString().Trim() }
    $credentials | ForEach-Object { Write-Host $_ }
} catch {
    Write-Host "Unable to enumerate credential manager"
}
Write-Host ""

# --- SECTION 2.5: SOFTWARE & DRIVER ENUMERATION (LPE) ---

Write-Host "===================================" -ForegroundColor Cyan
Write-Host "Software & Drivers (LPE Recon)" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan
Write-Host ""

# Windows Version
Write-Host "[+] Windows Version..." -ForegroundColor Yellow
$osInfo = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
if ($osInfo) {
    $build = "$($osInfo.CurrentMajorVersionNumber).$($osInfo.CurrentMinorVersionNumber).$($osInfo.CurrentBuildNumber).$($osInfo.UBR)"
    Write-Host "  $($osInfo.ProductName) (Build $build)" -ForegroundColor White
    Write-Host "  Edition: $($osInfo.EditionID)" -ForegroundColor Gray
}
Write-Host ""

# Installed Hotfixes (last 10)
Write-Host "[+] Installed Updates (last 10)..." -ForegroundColor Yellow
$wmicPath = "$env:SystemRoot\System32\wbem\wmic.exe"
if (Test-Path $wmicPath) {
    & $wmicPath qfe get Caption,Description,HotFixID,InstalledOn 2>$null | Select-Object -First 12
} else {
    # Fallback for systems without wmic (Windows 11+)
    $hotfixes = Get-HotFix -ErrorAction SilentlyContinue |
        Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue |
        Select-Object -First 10
    if ($hotfixes) {
        $hotfixes | ForEach-Object {
            $installed = if ($_.InstalledOn) { $_.InstalledOn.ToString("MM/dd/yyyy") } else { "Unknown" }
            Write-Host "  $($_.HotFixID) - $($_.Description) - $installed" -ForegroundColor White
        }
    } else {
        Write-Host "  Unable to retrieve hotfix information" -ForegroundColor Gray
    }
}
Write-Host ""

# Vulnerable Drivers (common targets)
Write-Host "[+] Potentially Vulnerable Drivers..." -ForegroundColor Yellow
$vulnDrivers = @(
    "RTCore64.sys", "RTCore32.sys",           # MSI Afterburner
    "DBUtil_2_3.sys",                          # Dell BIOS
    "AsIO.sys", "AsIO64.sys",                  # ASUS
    "WinRing0.sys", "WinRing0x64.sys",        # Various
    "SANDBOX.sys",                             # Avecto
    "elbycdio.sys",                            # ElbyCDIO
    "cpuz141.sys", "cpuz.sys",                 # CPU-Z
    "gdrv.sys",                                # Gigabyte
    "aswVmm.sys", "aswArPot.sys",             # Avast
    "NTIOLib.sys", "NTIOLib_X64.sys",         # MSI
    "AsUpIO.sys",                              # ASUS
    "BS_HWMIO64_W10.sys", "BS_I2cIo.sys"      # Biostar
)
$foundVuln = $false
foreach ($drv in $vulnDrivers) {
    $drvPath = Get-ChildItem -Path "$env:SystemRoot\System32\drivers\$drv" -ErrorAction SilentlyContinue
    if ($drvPath) {
        Write-Host "  [!] $drv" -ForegroundColor Red
        $foundVuln = $true
    }
}
if (-not $foundVuln) {
    Write-Host "  None of the common vulnerable drivers found" -ForegroundColor Green
}
Write-Host ""

# Third-party Software (common LPE targets)
Write-Host "[+] Installed Software (LPE targets)..." -ForegroundColor Yellow
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$software = Get-ItemProperty $regPaths -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -and $_.DisplayName -match '(VMware|VirtualBox|Citrix|TeamViewer|AnyDesk|7-Zip|WinRAR|PuTTY|FileZilla|Foxit|Adobe|Java|Python|Node|Git|VSCode|Notepad\+\+)' } |
    Select-Object DisplayName, DisplayVersion |
    Sort-Object DisplayName -Unique
if ($software) {
    $software | ForEach-Object {
        Write-Host "  $($_.DisplayName) - $($_.DisplayVersion)" -ForegroundColor White
    }
} else {
    Write-Host "  No common LPE target software found" -ForegroundColor Gray
}
Write-Host ""

# --- SECTION 3: PERMISSIONS SUMMARY ---

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PERMISSIONS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Initialize collections for report
$registryPermResults = @()
$folderPermResults = @()

# Test Registry Write Access
$regPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
)

Write-Host "[REGISTRY KEY PERMISSIONS]" -ForegroundColor Yellow
Write-Host ""
foreach ($regPath in $regPaths) {
    $canRead = $false
    $canWrite = $false

    # Test Read
    try {
        $null = Get-ItemProperty -Path $regPath -ErrorAction Stop
        $canRead = $true
    } catch {
        $canRead = $false
    }

    # Test Write
    try {
        $testValueName = "__TEST_WRITE_$(Get-Random)__"
        New-ItemProperty -Path $regPath -Name $testValueName -Value "test" -PropertyType String -ErrorAction Stop | Out-Null
        Remove-ItemProperty -Path $regPath -Name $testValueName -ErrorAction SilentlyContinue
        $canWrite = $true
    } catch {
        $canWrite = $false
    }

    $readStatus = if ($canRead) { "YES" } else { "NO " }
    $writeStatus = if ($canWrite) { "YES" } else { "NO " }
    $readColor = if ($canRead) { "Green" } else { "Red" }
    $writeColor = if ($canWrite) { "Green" } else { "Red" }

    # Store for report
    $registryPermResults += @{Path=$regPath; Read=$canRead; Write=$canWrite}

    Write-Host "  $regPath" -ForegroundColor White
    Write-Host "    Read:  " -NoNewline
    Write-Host $readStatus -ForegroundColor $readColor -NoNewline
    Write-Host "  |  Write: " -NoNewline
    Write-Host $writeStatus -ForegroundColor $writeColor
    Write-Host ""
}

# Test Startup Folder Permissions
Write-Host "[STARTUP FOLDER PERMISSIONS]" -ForegroundColor Yellow
Write-Host ""
$startupFolders = @(
    @{Path="$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"; Name="User Startup"},
    @{Path="$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Startup"; Name="All Users Startup"}
)

foreach ($folder in $startupFolders) {
    $canRead = $false
    $canWrite = $false

    # Test Read
    try {
        $null = Get-ChildItem $folder.Path -ErrorAction Stop
        $canRead = $true
    } catch {
        $canRead = $false
    }

    # Test Write
    try {
        $testFile = Join-Path $folder.Path "__test_write_$(Get-Random).txt"
        New-Item -Path $testFile -ItemType File -ErrorAction Stop | Out-Null
        Remove-Item -Path $testFile -ErrorAction SilentlyContinue
        $canWrite = $true
    } catch {
        $canWrite = $false
    }

    $readStatus = if ($canRead) { "YES" } else { "NO " }
    $writeStatus = if ($canWrite) { "YES" } else { "NO " }
    $readColor = if ($canRead) { "Green" } else { "Red" }
    $writeColor = if ($canWrite) { "Green" } else { "Red" }

    # Store for report
    $folderPermResults += @{Name=$folder.Name; Path=$folder.Path; Read=$canRead; Write=$canWrite}

    Write-Host "  $($folder.Name): $($folder.Path)" -ForegroundColor White
    Write-Host "    Read:  " -NoNewline
    Write-Host $readStatus -ForegroundColor $readColor -NoNewline
    Write-Host "  |  Write: " -NoNewline
    Write-Host $writeStatus -ForegroundColor $writeColor
    Write-Host ""
}

# Test Scheduled Task Creation
Write-Host "[SCHEDULED TASK PERMISSIONS]" -ForegroundColor Yellow
Write-Host ""
$canCreateTask = $false
try {
    $taskName = "__test_task_$(Get-Random)__"
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo test"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(24)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -ErrorAction Stop | Out-Null
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    $canCreateTask = $true
} catch {
    $canCreateTask = $false
}

$taskStatus = if ($canCreateTask) { "YES - Can create scheduled tasks" } else { "NO  - Cannot create scheduled tasks" }
$taskColor = if ($canCreateTask) { "Green" } else { "Red" }
Write-Host "  Create Scheduled Task: " -NoNewline
Write-Host $taskStatus -ForegroundColor $taskColor
Write-Host ""

# User Context
Write-Host "[CURRENT USER CONTEXT]" -ForegroundColor Yellow
Write-Host ""

if ($script:ConstrainedMode) {
    $currentUserName = $env:USERNAME
    $isAdmin = $false
    Write-Host "  Username: " -NoNewline
    Write-Host "$env:USERDOMAIN\$env:USERNAME" -ForegroundColor Cyan
    Write-Host "  Admin:    " -NoNewline
    Write-Host "UNKNOWN (Constrained Language Mode)" -ForegroundColor Yellow
    Write-Host "  Language: " -NoNewline
    Write-Host "Constrained" -ForegroundColor Red
} else {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
    $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    $currentUserName = $currentUser.Name

    Write-Host "  Username: " -NoNewline
    Write-Host "$($currentUser.Name)" -ForegroundColor Cyan
    Write-Host "  Admin:    " -NoNewline
    if ($isAdmin) {
        Write-Host "YES - Running with Administrator privileges" -ForegroundColor Green
    } else {
        Write-Host "NO  - Running with standard user privileges" -ForegroundColor Yellow
    }
}
Write-Host ""

# --- SECTION 4: REPORT GENERATION ---

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Generating Report..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$reportContent = @"
Security Report - $(Get-Date -Format "yyyy/MM/dd HH:mm")
=======================================

CURRENT USER CONTEXT
=======================================
Username:      $(if ($script:ConstrainedMode) { "$env:USERDOMAIN\$env:USERNAME" } else { $currentUserName })
Administrator: $(if ($script:ConstrainedMode) { 'Unknown (CLM)' } elseif ($isAdmin) { 'Yes' } else { 'No' })
Language Mode: $(if ($script:ConstrainedMode) { 'Constrained' } else { 'Full' })

SECURITY CONFIGURATION AUDIT
=======================================
$(if ($script:ConstrainedMode) { 'Skipped due to Constrained Language Mode' } else { '' })
"@

foreach ($result in $results) {
    $reportContent += @"
Check:  $($result.CheckName)
Status: $($result.Status)
Info:   $($result.Message)
"@
    if ($result.Status -eq 'Bad' -and $result.ReplicationCmd) {
        $reportContent += "Replication Commands:`n"
        $result.ReplicationCmd -split "`n" | ForEach-Object {
            $reportContent += "  $_`n"
        }
    }
    $reportContent += "---------------------------------------`n"
}

$reportContent += @"

PERSISTENCE ENUMERATION
=======================================

Registry Run Keys (HKLM):
"@
try {
    $hklmRun = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
    if ($hklmRun) {
        $hklmRun.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
            $reportContent += "  $($_.Name): $($_.Value)`n"
        }
    } else {
        $reportContent += "  (empty)`n"
    }
} catch { $reportContent += "  (unable to read)`n" }

$reportContent += @"

Registry Run Keys (HKCU):
"@
try {
    $hkcuRun = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
    if ($hkcuRun) {
        $hkcuRun.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
            $reportContent += "  $($_.Name): $($_.Value)`n"
        }
    } else {
        $reportContent += "  (empty)`n"
    }
} catch { $reportContent += "  (unable to read)`n" }

$reportContent += @"

Boot Execute:
"@
if ($bootExec) {
    $reportContent += "  $($bootExec.BootExecute -join ', ')"
    if (($bootExec.BootExecute -join ', ') -eq "autocheck autochk *") {
        $reportContent += " (Default - OK)`n"
    } else {
        $reportContent += " (Non-default - Review!)`n"
    }
} else {
    $reportContent += "  (unable to read)`n"
}

$reportContent += @"

PERMISSIONS SUMMARY
=======================================

Registry Key Permissions:
"@
foreach ($reg in $registryPermResults) {
    $readStr = if ($reg.Read) { "YES" } else { "NO" }
    $writeStr = if ($reg.Write) { "YES" } else { "NO" }
    $reportContent += "  $($reg.Path)`n"
    $reportContent += "    Read: $readStr  |  Write: $writeStr`n"
}

$reportContent += @"

Startup Folder Permissions:
"@
foreach ($folder in $folderPermResults) {
    $readStr = if ($folder.Read) { "YES" } else { "NO" }
    $writeStr = if ($folder.Write) { "YES" } else { "NO" }
    $reportContent += "  $($folder.Name): $($folder.Path)`n"
    $reportContent += "    Read: $readStr  |  Write: $writeStr`n"
}

$reportContent += @"

Scheduled Task Creation: $(if ($canCreateTask) { 'YES - Can create scheduled tasks' } else { 'NO - Cannot create scheduled tasks' })

=======================================
End of Report
=======================================
"@

$outputFile = "SecurityReport_$(Get-Date -Format yyyyMMdd_HHmmss).txt"
try {
    Set-Content -Path $outputFile -Value $reportContent -ErrorAction Stop
    Write-Host "Security report saved to '$outputFile'" -ForegroundColor Green
} catch {
    Write-Host "Failed to save security report to '$outputFile'. Error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Scan Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Read-Host "Press Enter to exit..."
