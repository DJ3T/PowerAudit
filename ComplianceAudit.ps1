# PowerShell Vulnerability & Compliance Scan Script (PS5-compatible)

$ErrorActionPreference = "Continue"
$report = New-Object System.Text.StringBuilder

# 1. System Information
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem
    $osName = $osInfo.Caption
    $osVer  = $osInfo.Version
    $hostname = $osInfo.CSName
} catch {
    $hostname = $env:COMPUTERNAME
    $osName = "(Unknown)"
    $osVer = "(Unknown)"
}

$report.AppendLine("===== Vulnerability Scan Report for $hostname =====") | Out-Null
$report.AppendLine("OS Version: $osName (Version $osVer)") | Out-Null

# Latest Patch
try {
    $latestHotFix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
} catch { $latestHotFix = $null }

if ($latestHotFix) {
    if ($latestHotFix.InstalledOn -is [DateTime]) {
        $report.AppendLine("Latest Hotfix: $($latestHotFix.HotFixID) installed on $($latestHotFix.InstalledOn.ToShortDateString())") | Out-Null
    } else {
        $report.AppendLine("Latest Hotfix: $($latestHotFix.HotFixID) (installation date unavailable)") | Out-Null
    }
} else {
    $report.AppendLine("Latest Hotfix: None found") | Out-Null
}

# 2. Firewall
try { $fwService = Get-Service -Name MpsSvc -ErrorAction Stop } catch { $fwService = $null }

if ($fwService -and $fwService.Status -ne "Running") {
    $report.AppendLine("Firewall: Windows Firewall service is STOPPED") | Out-Null
} else {
    try { $profiles = Get-NetFirewallProfile -All } catch { $profiles = $null }

    if ($profiles) {
        foreach ($prof in $profiles) {
            if ($prof.Enabled) {
                $status = "Enabled"
            } else {
                $status = "Disabled"
            }
            $report.AppendLine("Firewall Profile $($prof.Name): $status") | Out-Null
        }
    } else {
        $report.AppendLine("Firewall: Unable to retrieve firewall profiles") | Out-Null
    }
}

# 3. Antivirus
$avFound = $false

try {
    $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntivirusProduct
} catch { $avProducts = @() }

if ($avProducts.Count -gt 0) {
    foreach ($av in $avProducts) {
        $avFound = $true

        $onOffBits = $av.productState -band 0xF000
        $sigBits   = $av.productState -band 0x00F0

        switch ($onOffBits) {
            0x0000 { $avState = "Off" }
            0x1000 { $avState = "On" }
            0x2000 { $avState = "Snoozed" }
            0x3000 { $avState = "Expired" }
            default { $avState = "Unknown" }
        }

        switch ($sigBits) {
            0x0000 { $sigState = "Up-to-date" }
            0x0010 { $sigState = "Out-of-date" }
            default { $sigState = "Unknown" }
        }

        $report.AppendLine("Antivirus: $($av.displayName) - State: $avState, Signatures: $sigState") | Out-Null
    }
}

if (-not $avFound) {
    try { $defender = Get-Service WinDefend -ErrorAction Stop } catch { $defender = $null }

    if ($defender -and $defender.Status -eq "Running") {
        $avFound = $true
        try {
            $mp = Get-MpComputerStatus
            if ($mp.AVSignatureAge -lt 1) { $sigStatus = "Up-to-date" } else { $sigStatus = "Out-of-date" }
            if ($mp.AMRunning) { $rt = "On" } else { $rt = "Off" }
            $report.AppendLine("Antivirus: Windows Defender - State: $rt, Signatures: $sigStatus") | Out-Null
        } catch {
            $report.AppendLine("Antivirus: Windows Defender running") | Out-Null
        }
    }
}

if (-not $avFound) {
    $report.AppendLine("Antivirus: None detected") | Out-Null
}

# 4. SMBv1
try {
    $smbFeature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
    if ($smbFeature.State -eq "Enabled") {
        $report.AppendLine("SMBv1: Enabled (unsafe)") | Out-Null
    } else {
        $report.AppendLine("SMBv1: Disabled") | Out-Null
    }
} catch {
    $report.AppendLine("SMBv1: Unknown") | Out-Null
}

# 5. RDP
try {
    $rdp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections
    if ($rdp.fDenyTSConnections -eq 0) {
        $report.AppendLine("RDP: Enabled") | Out-Null
    } else {
        $report.AppendLine("RDP: Disabled") | Out-Null
    }
} catch {
    $report.AppendLine("RDP: Unknown") | Out-Null
}

# 6. UAC
try {
    $uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA
    if ($uac.EnableLUA -eq 1) { $uacStatus = "Enabled" } else { $uacStatus = "Disabled" }
    $report.AppendLine("UAC: $uacStatus") | Out-Null
} catch {
    $report.AppendLine("UAC: Unknown") | Out-Null
}

# 7. User Accounts
try {
    $guest = Get-LocalUser -Name "Guest"
    if ($guest.Enabled) { $report.AppendLine("Guest Account: Enabled") } else { $report.AppendLine("Guest Account: Disabled") }
} catch {}

try {
    $admin = Get-LocalUser | Where-Object { $_.SID -match "-500$" }
    if ($admin.Enabled) { $report.AppendLine("Builtin Admin: Enabled") } else { $report.AppendLine("Builtin Admin: Disabled") }
} catch {}

try {
    $nopass = Get-LocalUser | Where-Object { $_.Enabled -and -not $_.PasswordRequired }
    if ($nopass.Count -gt 0) {
        $report.AppendLine("Accounts without password requirement: $($nopass.Name -join ', ')")
    } else {
        $report.AppendLine("Password Policy: All accounts require a password")
    }
} catch {}

# 8. Listening Ports
try {
    $listeners = Get-NetTCPConnection -State Listen
    $report.AppendLine("Open Listening Ports:") | Out-Null

    $unique = $listeners | Select-Object LocalPort, OwningProcess -Unique
    foreach ($conn in $unique | Sort-Object LocalPort) {
        try { $proc = (Get-Process -Id $conn.OwningProcess).ProcessName } catch { $proc = "PID $($conn.OwningProcess)" }
        $report.AppendLine(" - Port $($conn.LocalPort) ($proc)") | Out-Null
    }
} catch {
    $report.AppendLine("Listening Ports: Access denied or none") | Out-Null
}

Write-Host $report.ToString()
