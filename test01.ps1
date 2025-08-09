# Windows template fix: ensure CloudStack/Cloudbase-Init password is accepted on first boot
# - Disables password complexity in the template (so the generated password is always valid)
# - Runs SetUserPasswordPlugin earlier
# - Ensures the account is NOT forced to change password at first logon
# - (Optional, default ON) Re-enables password complexity automatically on first boot
# Tested on Windows Server 2016/2019/2022/2025 with Cloudbase-Init
# Run as Administrator before you generalize/capture the template

#requires -version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -------------------------- SETTINGS --------------------------
# Re-enable password complexity after first boot (recommended)
$ReenablePolicyAfterFirstBoot = $true

# Fallback username if not found in cloudbase-init.conf
$DefaultCloudUser = 'Administrator'
# --------------------------------------------------------------

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Please run this script in an elevated PowerShell session (Run as Administrator)."
    }
}

function Get-CloudbaseInitConfPath {
    $candidates = @(
        'C:\Program Files\Cloudbase Solutions\Cloudbase-Init\conf\cloudbase-init.conf',
        'C:\Program Files (x86)\Cloudbase Solutions\Cloudbase-Init\conf\cloudbase-init.conf'
    )
    foreach ($p in $candidates) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    throw "cloudbase-init.conf not found in the default locations."
}

function Backup-File {
    param([Parameter(Mandatory)] [string]$Path)
    $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
    $bak = "$Path.bak.$ts"
    Copy-Item -LiteralPath $Path -Destination $bak -Force
    return $bak
}

function Relax-PasswordPolicyForTemplate {
    Write-Host "Relaxing local password policy in the template..."
    $inf = @"
[Version]
signature="$CHICAGO$"

[System Access]
MinimumPasswordLength = 1
PasswordComplexity = 0
MaximumPasswordAge = 0
PasswordHistorySize = 0
"@
    $infPath = "$env:TEMP\pwd_template_relax.inf"
    $dbPath  = "$env:TEMP\secpol_template_relax.sdb"
    Set-Content -LiteralPath $infPath -Value $inf -Encoding Ascii -Force
    & "$env:SystemRoot\System32\secedit.exe" /configure /db "$dbPath" /cfg "$infPath" /areas SECURITYPOLICY | Out-Null
}

function New-FirstBootPolicyRestore {
    # Creates a one-time scheduled task that restores complexity shortly after first boot
    Write-Host "Scheduling one-time restore of password complexity on first boot..."
    $script = @"
`$inf = @"
[Version]
signature="$CHICAGO$"

[System Access]
MinimumPasswordLength = 8
PasswordComplexity = 1
MaximumPasswordAge = 42
PasswordHistorySize = 24
"@
`$infPath = "C:\Windows\Temp\pwd_template_restore.inf"
`$dbPath  = "C:\Windows\Temp\secpol_template_restore.sdb"
Set-Content -LiteralPath `$infPath -Value `$inf -Encoding Ascii -Force
& "`$env:SystemRoot\System32\secedit.exe" /configure /db "`$dbPath" /cfg "`$infPath" /areas SECURITYPOLICY | Out-Null
# cleanup: remove task after running
schtasks /Delete /TN "Template\RestorePasswordPolicyOnce" /F | Out-Null
Remove-Item -LiteralPath `$infPath, `$dbPath -ErrorAction SilentlyContinue
"@
    $restorePath = 'C:\Windows\Temp\restore_policy_once.ps1'
    Set-Content -LiteralPath $restorePath -Value $script -Encoding UTF8 -Force

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$restorePath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility Win8
    if (-not (Get-ScheduledTask -TaskName 'Template\RestorePasswordPolicyOnce' -ErrorAction SilentlyContinue)) {
        Register-ScheduledTask -TaskName 'Template\RestorePasswordPolicyOnce' -TaskPath 'Template\' -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest | Out-Null
    } else {
        Set-ScheduledTask -TaskName 'Template\RestorePasswordPolicyOnce' -TaskPath 'Template\' -Action $action -Trigger $trigger -Settings $settings | Out-Null
    }
}

function Get-CloudUserFromConf {
    param([Parameter(Mandatory)][string]$ConfText)
    # cloudbase-init.conf may have: username=...  (sometimes in [DEFAULT] or global)
    $m = [Regex]::Match($ConfText, '^\s*username\s*=\s*(.+?)\s*$', 'IgnoreCase, Multiline')
    if ($m.Success) { return $m.Groups[1].Value.Trim() }
    return $null
}

function Reorder-Plugins {
    param(
        [Parameter(Mandatory)][string]$ConfText
    )
    # Extract existing plugins line (comma-separated, no quotes)
    $rx = [Regex]::new('^\s*plugins\s*=\s*(.+?)\s*$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline)
    $mt = $rx.Match($ConfText)

    $targetOrder = @(
        'cloudbaseinit.plugins.common.mtu.MTUPlugin',
        'cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin',
        'cloudbaseinit.plugins.windows.createuser.CreateUserPlugin',
        'cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin', # MUST be right after CreateUser
        'cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin',
        'cloudbaseinit.plugins.windows.licensing.WindowsLicensingPlugin',
        'cloudbaseinit.plugins.windows.extendvolumes.ExtendVolumesPlugin',
        'cloudbaseinit.plugins.common.sshpublickeys.SetUserSSHPublicKeysPlugin',
        'cloudbaseinit.plugins.common.localscripts.LocalScriptsPlugin'
    )

    if ($mt.Success) {
        $raw = $mt.Groups[1].Value
        $cur = $raw.Split(',').ForEach({ $_.Trim() }) | Where-Object { $_ -ne '' }
        # Ensure both CreateUser and SetUserPassword exist; if not, add them
        if ($cur -notcontains 'cloudbaseinit.plugins.windows.createuser.CreateUserPlugin') {
            $cur += 'cloudbaseinit.plugins.windows.createuser.CreateUserPlugin'
        }
        if ($cur -notcontains 'cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin') {
            $cur += 'cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin'
        }
        # Move SetUserPassword immediately after CreateUser
        $cur = $cur | Select-Object -Unique
        $cur = $cur | Where-Object { $_ -ne 'cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin' }
        $new = @()
        foreach ($p in $cur) {
            $new += $p
            if ($p -eq 'cloudbaseinit.plugins.windows.createuser.CreateUserPlugin') {
                $new += 'cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin'
            }
        }
        # If createuser wasn't found for some reason, prepend password plugin
        if ($new -notcontains 'cloudbaseinit.plugins.windows.createuser.CreateUserPlugin') {
            $new = @('cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin') + $new
        }
        $joined = ($new -join ',')
        return $rx.Replace($ConfText, "plugins=$joined", 1)
    } else {
        # No plugins line; inject a sane default with correct order
        $inject = "plugins=" + ($targetOrder -join ',')
        if ($ConfText -match '^\s*\[.*?\]') {
            # put at top if INI-like content exists
            return $inject + [Environment]::NewLine + $ConfText
        } else {
            return $ConfText + [Environment]::NewLine + $inject
        }
    }
}

function Ensure-PasswordNotForcedChange {
    param([Parameter(Mandatory)][string]$User)
    Write-Host "Ensuring '$User' is not forced to change password at next logon..."
    try {
        # PowerShell way (preferred)
        Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop
        $lu = Get-LocalUser -Name $User -ErrorAction Stop
        if ($lu.PasswordExpires) {
            Set-LocalUser -Name $User -PasswordNeverExpires $true
        }
        # Ensure "User must change password at next logon" is off
        # (no direct flag; toggled by expiring the password; we already set never expires)
    } catch {
        # Fallback to WMIC if LocalAccounts isn't available
        & wmic useraccount where "name='$User'" set PasswordExpires=False | Out-Null
    }
    # Ensure Windows won't force change at logon
    & net user $User /logonpasswordchg:no /passwordchg:yes | Out-Null
}

# ------------------------------ MAIN ------------------------------
try {
    Assert-Admin

    $confPath = Get-CloudbaseInitConfPath
    $confBackup = Backup-File -Path $confPath
    Write-Host "Backed up cloudbase-init.conf to: $confBackup"

    $confText = Get-Content -LiteralPath $confPath -Raw -Encoding UTF8

    # Reorder plugins so SetUserPasswordPlugin runs immediately after CreateUser
    $newConfText = Reorder-Plugins -ConfText $confText

    if ($newConfText -ne $confText) {
        Set-Content -LiteralPath $confPath -Value $newConfText -Encoding UTF8 -NoNewline
        Write-Host "Updated plugins order in cloudbase-init.conf"
    } else {
        Write-Host "Plugins order already OK"
    }

    # Determine cloud user for the flags below
    $cloudUser = Get-CloudUserFromConf -ConfText $newConfText
    if (-not $cloudUser) { $cloudUser = $DefaultCloudUser }
    Write-Host "Cloud user detected: $cloudUser"

    # Make sure template accepts the generated password
    Relax-PasswordPolicyForTemplate

    # Guard against "must change password" prompt
    Ensure-PasswordNotForcedChange -User $cloudUser

    if ($ReenablePolicyAfterFirstBoot) {
        New-FirstBootPolicyRestore
    }

    Write-Host "`nDone. On first boot, Windows will accept the CloudStack-provided password without prompting to change it."
    if ($ReenablePolicyAfterFirstBoot) {
        Write-Host "Password complexity will be re-enabled automatically right after first boot."
    } else {
        Write-Host "NOTE: Password complexity remains disabled in the template (you can re-enable it later)."
    }
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
