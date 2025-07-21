# <--- Begin of Script --->
# PowerShell Vulnerability & Compliance Scan Script
# This script gathers system security settings and outputs a compliance report.
# It is designed to be non-intrusive (read-only) and safe to run on a machine.
# Requirements: PowerShell 5 or later. Run as Administrator for best results.

# Ensure errors don't stop execution (so one failed check doesn't terminate script)
$ErrorActionPreference = "Continue"

# StringBuilder to accumulate report lines
$report = New-Object -TypeName System.Text.StringBuilder

# 1. System Information and Latest Patch
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem
    $osName = $osInfo.Caption
    $osVer  = $osInfo.Version
    $hostname = $osInfo.CSName   # Computer name
} catch {
    $hostname = $env:COMPUTERNAME
    $osName = "(OS name unknown)"
    $osVer = "(OS version unknown)"
}
$report.AppendLine("===== Vulnerability Scan Report for $hostname =====") | Out-Null
$report.AppendLine("OS Version: $osName (Version $osVer)") | Out-Null

# Check latest installed hotfix (patch) date
try {
    $latestHotFix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
} catch {
    $latestHotFix = $null
}
if ($latestHotFix) {
    $patchID = $latestHotFix.HotFixID
    # Some hotfix entries might have no date (e.g., if run as non-admin). Handle that:
    if ($latestHotFix.InstalledOn -is [DateTime] -and $latestHotFix.InstalledOn -gt 0) {
        $patchDate = $latestHotFix.InstalledOn.ToShortDateString()
        $report.AppendLine("Latest Hotfix: $patchID (installed on $patchDate)") | Out-Null
    } else {
        $report.AppendLine("Latest Hotfix: $patchID (installation date not available)") | Out-Null
    }
} else {
    $report.AppendLine("Latest Hotfix: <None found> (system may have no updates or access denied)") | Out-Null
}

# 2. Windows Firewall status
try {
    $fwService = Get-Service -Name MpsSvc -ErrorAction Stop
} catch {
    $fwService = $null
}
if ($fwService -and $fwService.Status -ne 'Running') {
    $report.AppendLine("Firewall: Windows Firewall service is STOPPED ❌") | Out-Null
} else {
    # Get status of each firewall profile
    try {
        $profiles = Get-NetFirewallProfile -All
    } catch {
        $profiles = $null
    }
    if ($profiles) {
        # Compose status for each profile
        $profileStatusList = @()
        foreach ($prof in $profiles) {
            $status = $prof.Enabled ? "Enabled ✅" : "Disabled ❌"
            $profileStatusList += ($prof.Name + "=" + $status)
        }
        $report.AppendLine("Firewall Profiles: " + ($profileStatusList -join "; ")) | Out-Null
    } else {
        $report.AppendLine("Firewall: <Unable to retrieve firewall profile status>") | Out-Null
    }
}

# 3. Antivirus status (name, running state, signature status)
# First, try SecurityCenter2 WMI (works on Windows 10/11 client OS)
$avFound = $false
try {
    $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntivirusProduct -ErrorAction Stop
} catch {
    $avProducts = @()
}
if ($avProducts.Count -gt 0) {
    foreach ($av in $avProducts) {
        $avFound = $true
        $avName = $av.displayName
        $stateCode = $av.productState
        # Decode productState bits: 
        $onOffBits = $stateCode -band 0xF000
        $sigBits   = $stateCode -band 0x00F0
        $avState = switch ($onOffBits) {
            0x0000 { "Off" }
            0x1000 { "On" }
            0x2000 { "Snoozed/Disabled" }
            0x3000 { "Expired" }
            default { "Unknown" }
        }
        $sigState = switch ($sigBits) {
            0x0000 { "Up-to-date" }
            0x0010 { "Out-of-date" }
            default { "Unknown" }
        }
        $report.AppendLine("Antivirus: $avName – State: $avState, Signatures: $sigState") | Out-Null
    }
}
# If WMI didn't find an AV (possible on servers), check Windows Defender or common AV services
if (-not $avFound) {
    # Check if Windows Defender is present
    try {
        $defenderService = Get-Service -Name WinDefend -ErrorAction Stop
    } catch {
        $defenderService = $null
    }
    if ($defenderService -and $defenderService.Status -eq 'Running') {
        # Windows Defender is running
        $avFound = $true
        # Try to get Defender status via Defender module
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            $realTimeProt = $mp.AMRunning  # boolean (real-time protection)
            $sigAge = $mp.AVSignatureAge   # days since last signature update
            $sigStatus = ($sigAge -lt 1) ? "Up-to-date" : "Out-of-date"
            $rtStatus = $realTimeProt ? "On" : "Off"
            $report.AppendLine("Antivirus: Windows Defender – State: $rtStatus, Signatures: $sigStatus") | Out-Null
        } catch {
            # Fallback if Get-MpComputerStatus not available
            $report.AppendLine("Antivirus: Windows Defender is running (real-time protection enabled)") | Out-Null
        }
    } else {
        # As a last resort, try to detect any other AV by common services names (optional)
        try {
            $possibleAV = Get-Service | Where-Object { $_.DisplayName -like "*Anti*Virus*" -or $_.DisplayName -like "*Endpoint Protection*" } | Select-Object -First 1
        } catch {
            $possibleAV = $null
        }
        if ($possibleAV) {
            $avFound = $true
            $avStatus = ($possibleAV.Status -eq 'Running') ? "Running" : $possibleAV.Status
            $report.AppendLine("Antivirus: $($possibleAV.DisplayName) – Status: $avStatus") | Out-Null
        }
    }
}
if (-not $avFound) {
    $report.AppendLine("Antivirus: <No antivirus detected> ❌") | Out-Null
}

# 4. SMBv1 protocol status (should be disabled in modern systems)
$SMB1Enabled = $null
# Try using Windows Optional Feature (works on Windows 10/11, Server 2016+)
try {
    $smbFeature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
    if ($smbFeature.State -eq "Enabled") { $SMB1Enabled = $true }
    elseif ($smbFeature.State -match "Disabled" -or $smbFeature.State -match "Removed") { $SMB1Enabled = $false }
} catch {
    # Fallback: check registry for SMB1
    try {
        $smbReg = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name SMB1 -ErrorAction Stop
        $SMB1Enabled = ($smbReg.SMB1 -eq 1)
    } catch {
        # If registry key not present, on older OS that likely means SMB1 is enabled by default
        $SMB1Enabled = $true
    }
}
if ($SMB1Enabled) {
    $report.AppendLine("SMBv1 Protocol: ENABLED ❌ (Unsafe, should be disabled)") | Out-Null
} elseif ($SMB1Enabled -ne $null) {
    $report.AppendLine("SMBv1 Protocol: Disabled ✅") | Out-Null
} else {
    $report.AppendLine("SMBv1 Protocol: <Unknown>") | Out-Null
}

# 5. Remote Desktop (RDP) status
try {
    $rdpSetting = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" -Name fDenyTSConnections -ErrorAction Stop
    $rdpEnabled = ($rdpSetting.fDenyTSConnections -eq 0)
} catch {
    $rdpEnabled = $false
}
if ($rdpEnabled) {
    $report.AppendLine("Remote Desktop (RDP): ENABLED ⚠️ (Remote connections allowed - ensure this is needed and secured)") | Out-Null
} else {
    $report.AppendLine("Remote Desktop (RDP): Disabled (no inbound remote desktop)") | Out-Null
}

# 6. User Account Control (UAC) status
try {
    $uac = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -Name EnableLUA -ErrorAction Stop
    $uacEnabled = ($uac.EnableLUA -eq 1)
} catch {
    $uacEnabled = $true  # assume enabled if we cannot read it
}
if ($uacEnabled) {
    $report.AppendLine("User Account Control (UAC): Enabled ✅") | Out-Null
} else {
    $report.AppendLine("User Account Control (UAC): **DISABLED** ❌ (Not recommended)") | Out-Null
}

# 7. Accounts: Guest account status and password policy checks
# Guest account
try {
    $guest = Get-LocalUser -Name 'Guest' -ErrorAction Stop
    $guestEnabled = $guest.Enabled
} catch {
    $guestEnabled = $null
}
if ($guestEnabled -ne $null) {
    if ($guestEnabled) {
        $report.AppendLine("Guest Account: ENABLED ❌ (Should be disabled)") | Out-Null
    } else {
        $report.AppendLine("Guest Account: Disabled ✅") | Out-Null
    }
}

# Built-in Administrator account (RID -500)
try {
    $adminAcct = Get-LocalUser | Where-Object { $_.SID -match '-500$' }
} catch {
    $adminAcct = $null
}
if ($adminAcct) {
    if ($adminAcct.Enabled) {
        $report.AppendLine("Built-in Administrator: Enabled ⚠️ (Use a strong password and/or rename if not already)") | Out-Null
    } else {
        $report.AppendLine("Built-in Administrator: Disabled (default admin account is off)") | Out-Null
    }
}

# Check for any enabled accounts with no password required
try {
    $noPassAccounts = Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.PasswordRequired -eq $false }
} catch {
    $noPassAccounts = @()
}
if ($noPassAccounts.Count -gt 0) {
    $npNames = ($noPassAccounts.Name -join ", ")
    $report.AppendLine("Accounts with no required password: $npNames ❌ (These accounts have no password!)") | Out-Null
} else {
    $report.AppendLine("Password Policy: All enabled local accounts require a password (no blank passwords)") | Out-Null
}

# 8. Open listening ports and associated processes
try {
    $listeners = Get-NetTCPConnection -State Listen
} catch {
    $listeners = $null
}
if ($listeners) {
    $report.AppendLine("Open Listening Ports:") | Out-Null
    # Get unique ports (to avoid duplicates for IPv4/IPv6 of same service)
    $uniquePorts = $listeners | Select-Object -Unique -Property LocalPort, OwningProcess
    foreach ($conn in $uniquePorts | Sort-Object LocalPort) {
        $port = $conn.LocalPort
        $pid  = $conn.OwningProcess
        $procName = ""
        try {
            $proc = Get-Process -Id $pid -ErrorAction Stop
            $procName = $proc.ProcessName
        } catch {
            $procName = "PID $pid"
        }
        # Determine if port is bound to all interfaces or specific (for info)
        $portAddresses = ($listeners | Where-Object { $_.LocalPort -eq $port }).LocalAddress
        $addrDesc = ""
        if ($portAddresses -contains '0.0.0.0' -or $portAddresses -contains '::') {
            $addrDesc = "all interfaces"
        } elseif ($portAddresses | Where-Object { $_ -notlike '127.*' } ) {
            # if any address not loopback
            $addrDesc = "network interfaces"
        } else {
            $addrDesc = "local (loopback) only"
        }
        $report.AppendLine(" - Port $port ($procName) [$addrDesc]") | Out-Null
    }
} else {
    $report.AppendLine("Open Listening Ports: <None or access denied>") | Out-Null
}

# 9. (Optional) Additional checks can be added here, e.g., ensure certain services are or are not running, etc.

# Output the report to screen
Write-Host $report.ToString()
# <--- End of Script --->
