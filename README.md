# SeChecks

Windows security configuration auditing and persistence enumeration. Combines defensive security checks (VBS, Credential Guard, TPM 2.0, ASR, Windows Defender) with offensive security reconnaissance (registry persistence, startup locations, scheduled tasks, permissions testing).

## Features

The script is organized into four sections:

### Section 1: Security Configuration Audit

#### Core Windows 11 Security
- **Virtualization-Based Security (VBS)** - Checks VBS and Memory Integrity (HVCI) status
- **Credential Guard** - Verifies credential theft protection
- **TPM 2.0** - Validates TPM presence, version, and readiness
- **Secure Boot** - Confirms UEFI Secure Boot status

#### Windows Defender - Enhanced Checks
- **Enhanced Defender Status** - Real-time protection, cloud protection, network protection, tamper protection, PUA protection, and signature age
- **Attack Surface Reduction (ASR) Rules** - Checks configured ASR rules that prevent Office exploits and script-based attacks
- **Controlled Folder Access** - Anti-ransomware protection for user folders
- **Defender Exclusions** - Lists and counts path, extension, process, and IP exclusions (security risk if excessive)

#### Traditional Security Checks
- **Firewall** - All profile statuses
- **User Account Control (UAC)** - Prompt configuration
- **Windows Update** - Service status, pending updates, and last update time
- **BitLocker** - Drive encryption status

#### Authentication & Access Control
- **Windows Hello for Business** - Modern authentication configuration
- **Guest Account** - Disabled/enabled status
- **Windows LAPS** - Modern built-in LAPS and legacy LAPS detection

#### Network Security
- **Remote Desktop (RDP)** - Status, NLA, SSL/TLS encryption, port configuration
- **SMBv1** - Deprecated protocol status
- **SMB Signing & Encryption** - Client/server signing requirements and encryption
- **Network Sharing** - File and printer sharing status

#### System Configuration
- **PowerShell Execution Policy** - Script execution restrictions
- **Audit Policy** - Logon/Logoff auditing configuration

### Section 2: Persistence Enumeration

Enumerates common persistence mechanisms used by malware and attackers:

- **Stored Credentials** - Windows Credential Manager entries
- **Registry Run Keys** - HKLM and HKCU Run/RunOnce keys
- **Startup Folders** - User and All Users startup directories
- **Scheduled Tasks** - Active scheduled tasks with user context
- **Auto-start Services** - Services configured for automatic startup
- **Winlogon Keys** - Shell, Userinit, and other Winlogon values
- **Boot Execute** - Session Manager boot execution entries
- **Image File Execution Options** - Debugger hijacking detection
- **AppInit_DLLs** - DLL injection via AppInit
- **LSA Packages** - Authentication and security packages

### Section 3: Permissions Summary

Tests current user's write access to persistence locations:

- **Registry Keys** - Write access to Run, RunOnce, Winlogon keys
- **Startup Folders** - Write access to user and all-users startup directories
- **Scheduled Tasks** - Ability to create scheduled tasks
- **User Context** - Current username and administrator status

### Section 4: Report Generation

Generates a timestamped security report (`SecurityReport_YYYYMMDD_HHMMSS.txt`) containing all security configuration results.

## Usage

### Local Execution
```powershell
# As Administrator (recommended for full checks)
PowerShell.exe -ExecutionPolicy Bypass -File ".\SeChecks.ps1"
```

### Remote Execution (IEX)
```powershell
# PowerShell download and execute
iex (iwr -UseBasicParsing https://raw.githubusercontent.com/moscowchill/SeChecks.ps1/main/SeChecks.ps1)

# Alternative with Invoke-Expression
powershell -ep bypass -c "iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/moscowchill/SeChecks.ps1/main/SeChecks.ps1')"
```

### LOLBIN Methods
```cmd
# Bitsadmin download
bitsadmin /transfer secjob /download /priority high https://raw.githubusercontent.com/moscowchill/SeChecks.ps1/main/SeChecks.ps1 %TEMP%\SeChecks.ps1 && powershell -ep bypass -f %TEMP%\SeChecks.ps1

# Certutil download
certutil -urlcache -split -f https://raw.githubusercontent.com/moscowchill/SeChecks.ps1/main/SeChecks.ps1 %TEMP%\SeChecks.ps1 && powershell -ep bypass -f %TEMP%\SeChecks.ps1
```

### Notes
- Most checks work without admin, but some (TPM, BitLocker, SMBv1, Audit Policy) require elevation
- Script clearly indicates which checks were skipped due to insufficient privileges

## Use Cases

- **Blue Team** - Audit security configuration, identify misconfigurations
- **Red Team** - Enumerate persistence mechanisms, test write permissions
- **Sysadmins** - Verify security baselines across endpoints

## Disclaimer

This script is provided as-is and without warranty. Use at your own risk. Only use on systems you own or have explicit authorization to test.
