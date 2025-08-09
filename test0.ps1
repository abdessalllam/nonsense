#requires -Version 5.1
<#
    CloudStack Windows Template Prep (Server 2016 → 2025)
    ----------------------------------------------------
    • Auto-elevates
    • Idempotent, noisy failures removed
    • Works online or with pre-downloaded MSIs

    Parameters you may care about:
      -CloudUser 'Administrator'         # account to set via Cloudbase-Init
      -CloudbaseInitVersion '1.1.6'      # versioned GitHub release
      -CloudbaseInitMsiPath 'C:\path\CloudbaseInitSetup_1_1_6_x64.msi'  # offline
      -VirtIOMsiPath 'C:\path\virtio-win-gt-x64.msi'                    # offline
      -SkipVirtIO, -SkipCloudbaseInit
#>

param(
    [string]$CloudUser = 'Administrator',
    [string]$CloudbaseInitVersion = '1.1.6',
    [string]$CloudbaseInitMsiPath = '',
    [string]$VirtIOMsiPath = '',
    [string]$VirtIOIsoDrive = '',  # e.g., 'E:' (mounted virtio-win ISO root)
    [switch]$SkipVirtIO,
    [switch]$SkipCloudbaseInit
)

# ------------------------ Self-elevate if not Admin ---------------------------
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "Elevation required. Relaunching as Administrator..." -ForegroundColor Yellow
    $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
    foreach ($k in $PSBoundParameters.Keys) {
        $val = $PSBoundParameters[$k]
        if ($val -is [System.Management.Automation.SwitchParameter]) {
            if ($val.IsPresent) { $argList += @("-$k") }
        } elseif ($null -ne $val -and "$val".Length -gt 0) {
            $escaped = '"' + ($val.ToString().Replace('"','`"')) + '"'
            $argList += @("-$k", $escaped)
        }
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo "powershell"
    $psi.Arguments = ($argList -join ' ')
    $psi.Verb = "RunAs"
    try { [System.Diagnostics.Process]::Start($psi) | Out-Null; exit } catch { exit 1 }
}


# ------------------------ Hardening defaults ----------------------------------
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$log = 'C:\cloudstack-prep.log'
$transcriptStarted = $false
try { Start-Transcript -Path $log -Append | Out-Null; $transcriptStarted = $true } catch {
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    try { Start-Transcript -Path "C:\cloudstack-prep_$timestamp.log" -Append | Out-Null; $transcriptStarted = $true } catch {}
}

function Step([string]$m) { Write-Host ">> $m" -ForegroundColor Cyan }
try { Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue } catch {}

# ------------------------ Helpers ---------------------------------------------
function Try-StartService {
    param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.StartType -ne 'Automatic') { try { Set-Service -Name $Name -StartupType Automatic } catch {} }
        if ($svc.Status -ne 'Running') { try { Start-Service -Name $Name -ErrorAction SilentlyContinue } catch {} }
        return $true
    }
    return $false
}

function Ensure-ServiceAutoStart {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [string[]]$DependsOn
    )
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { return }  # quiet skip if absent
    try {
        Set-Service -Name $Name -StartupType Automatic
        if ($svc.Status -ne 'Running') { Start-Service -Name $Name -ErrorAction SilentlyContinue }
        $reg = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
        New-Item -Path $reg -Force | Out-Null
        New-ItemProperty -Path $reg -Name 'DelayedAutoStart' -Value 0 -PropertyType DWord -Force | Out-Null
        if ($DependsOn -and $DependsOn.Count -gt 0) {
            $existing = (Get-ItemProperty -Path $reg -Name 'DependOnService' -ErrorAction SilentlyContinue).DependOnService
            if ($existing -is [string]) { $existing = @($existing) }
            if (-not $existing) { $existing = @() }
            $merged = ($existing + $DependsOn) | Where-Object { $_ } | Select-Object -Unique
            if ($merged.Count -gt 0) {
                New-ItemProperty -Path $reg -Name 'DependOnService' -Value $merged -PropertyType MultiString -Force | Out-Null
            }
        }
    } catch {}
}

# ------------------------ OS Optimisation -------------------------------------
function Optimize-OS {
    Step 'Enable RDP + NLA and open firewall'
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -PropertyType DWord -Force | Out-Null

    # Only touch TermService if present; otherwise skip quietly (some minimal images)
    if (Try-StartService -Name 'TermService') {
        # RDP firewall rules
        $ok = $false
        try { Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction Stop | Out-Null; $ok = $true } catch {}
        if (-not $ok) {
            foreach ($rule in @('RemoteDesktop-UserMode-In-TCP','RemoteDesktop-UserMode-In-UDP')) {
                try { Enable-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue | Out-Null } catch {}
            }
            # netsh fallback
            try { & netsh advfirewall firewall set rule group="remote desktop" new enable=Yes | Out-Null } catch {}
        }
    } else {
        Write-Verbose "TermService (Remote Desktop Services) not present; skipping RDP service start."
    }

    Step 'Wait for network at startup (pre-logon)'
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'SyncForegroundPolicy' -Value 1 -PropertyType DWord -Force | Out-Null
}

# ------------------------ Pagefile --------------------------------------------
function Fix-Pagefile {
    Step 'Set pagefile: system-managed'
    $cs = Get-WmiObject -Class Win32_ComputerSystem
    if ($cs.AutomaticManagedPagefile -ne $true) {
        $cs.AutomaticManagedPagefile = $true
        $cs.Put() | Out-Null
    }
}

# ------------------------ Cleanup ---------------------------------------------
function Safe-Cleanup {
    Step 'Clean TEMP and Windows Update cache'
    $targets = @("$env:TEMP","$env:WINDIR\Temp","C:\Windows\SoftwareDistribution\Download")
    foreach ($t in $targets) {
        if (Test-Path $t) {
            Get-ChildItem -Path $t -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Step 'Clear Event Logs (non-critical)'
    try { wevtutil el | ForEach-Object { try { wevtutil cl $_ } catch {} } } catch {}

    Step 'Component cleanup (best-effort)'
    try { DISM /Online /Cleanup-Image /StartComponentCleanup | Out-Null } catch {}
}

# ------------------------ VirtIO Guest Tools ----------------------------------

function Install-VirtIO {
    if ($SkipVirtIO) { Step 'Skip VirtIO (requested)'; return }
    Step 'Install VirtIO Guest Tools (MSI) and QEMU-GA (if available)'

    $arch = if ([Environment]::Is64BitOperatingSystem) {'x64'} else {'x86'}
    $msiName = "virtio-win-gt-$arch.msi"
    $msiPath = if ($VirtIOMsiPath) { $VirtIOMsiPath } else { Join-Path $env:TEMP $msiName }

    if (-not $VirtIOMsiPath) {
        $urls = @(
            "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/$msiName",
            "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/$msiName"
        )
        $downloaded = $false
        foreach ($u in $urls) {
            try {
                Step "Downloading VirtIO from: $u"
                Invoke-WebRequest -Uri $u -OutFile $msiPath -UseBasicParsing -ErrorAction Stop
                $downloaded = $true; break
            } catch {
                Write-Verbose "VirtIO download failed: $u"
            }
        }
        if (-not $downloaded) { throw "VirtIO MSI not downloaded from any source." }
    }

    if (-not (Test-Path $msiPath)) { throw "VirtIO MSI not found at $msiPath" }
    # Install ALL features silently
    $args = "/i `"$msiPath`" /qn /norestart ADDLOCAL=ALL"
    $p = Start-Process -FilePath msiexec.exe -ArgumentList $args -PassThru -Wait
    if ($p.ExitCode -ne 0) { throw "VirtIO installer exit code: $($p.ExitCode)" }

    # If drivers still not visible, optionally stage from ISO using pnputil
    $hasRedHatDrivers = $false
    try {
        $drivers = Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DriverProviderName -like '*Red Hat*' -or $_.Manufacturer -like '*Red Hat*' }
        if ($drivers) { $hasRedHatDrivers = $true }
    } catch {}

    if (-not $hasRedHatDrivers -and $VirtIOIsoDrive) {
        Step "Staging VirtIO drivers via pnputil from $VirtIOIsoDrive (fallback)"
        $infGlob = Join-Path "$VirtIOIsoDrive\" "*.inf"
        try {
            pnputil.exe /add-driver "$infGlob" /subdirs /install | Out-Null
            # Recheck
            $drivers = Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DriverProviderName -like '*Red Hat*' -or $_.Manufacturer -like '*Red Hat*' }
            if ($drivers) { $hasRedHatDrivers = $true }
        } catch {
            Write-Verbose "pnputil staging failed: $($_.Exception.Message)"
        }
    }

    # QEMU Guest Agent: try to start if installed; otherwise attempt from ISO if present
    $gaSvcNames = @('QEMU-GA','qemu-ga')
    $gaFound = $false
    foreach ($svc in $gaSvcNames) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            Ensure-ServiceAutoStart -Name $svc -DependsOn @('nsi','Tcpip')
            $gaFound = $true
        }
    }

    if (-not $gaFound -and $VirtIOIsoDrive) {
        $gaMsi = Join-Path "$VirtIOIsoDrive\guest-agent" "qemu-ga-x86_64.msi"
        if (Test-Path $gaMsi) {
            Step "Installing QEMU Guest Agent from $gaMsi"
            $gaArgs = "/i `"$gaMsi`" /qn /norestart"
            $gp = Start-Process -FilePath msiexec.exe -ArgumentList $gaArgs -PassThru -Wait
            if ($gp.ExitCode -eq 0) {
                foreach ($svc in $gaSvcNames) {
                    Ensure-ServiceAutoStart -Name $svc -DependsOn @('nsi','Tcpip')
                }
                $gaFound = $true
            } else {
                Write-Verbose "qemu-ga installer exit code: $($gp.ExitCode)"
            }
        }
    }
}


# ------------------------ Cloudbase-Init --------------------------------------
function Install-CloudbaseInit {
    if ($SkipCloudbaseInit) { Step 'Skip Cloudbase-Init (requested)'; return }

    Step "Install Cloudbase-Init ($CloudbaseInitVersion)"
    $arch = if ([Environment]::Is64BitOperatingSystem) {'x64'} else {'x86'}
    $vUnderscore = ($CloudbaseInitVersion -replace '\.','_')
    $msiName = "CloudbaseInitSetup_{0}_{1}.msi" -f $vUnderscore, $arch
    $msiPath = if ($CloudbaseInitMsiPath) { $CloudbaseInitMsiPath } else { Join-Path $env:TEMP $msiName }

    if (-not $CloudbaseInitMsiPath) {
        $url = "https://github.com/cloudbase/cloudbase-init/releases/download/$CloudbaseInitVersion/$msiName"
        Step "Downloading: $url"
        try {
            Invoke-WebRequest -Uri $url -OutFile $msiPath -UseBasicParsing -ErrorAction Stop
        } catch {
            throw "Failed to download Cloudbase-Init from $url : $($_.Exception.Message)"
        }
    }

    if (-not (Test-Path $msiPath)) { throw "Cloudbase-Init MSI not found at $msiPath" }

    $cbArgs = "/i `"$msiPath`" /qn /norestart RUN_CLOUDBASEINIT_SERVICE=1 SYSPREP_DISABLED=1"
    $proc = Start-Process -FilePath msiexec.exe -ArgumentList $cbArgs -PassThru -Wait
    if ($proc.ExitCode -ne 0) { throw "Cloudbase-Init installer exit code: $($proc.ExitCode)" }

    # Configure Cloudbase-Init
    Step 'Configure Cloudbase-Init for CloudStack password injection'
    $cbRoot   = "${env:ProgramFiles}\Cloudbase Solutions\Cloudbase-Init"
    $cbConfDir= Join-Path $cbRoot 'conf'
    $cbConf   = Join-Path $cbConfDir 'cloudbase-init.conf'
    if (-not (Test-Path $cbConfDir)) { New-Item -Path $cbConfDir -ItemType Directory -Force | Out-Null }

    $plugins = @(
        'cloudbaseinit.plugins.common.mtu.MTUPlugin',
        'cloudbaseinit.plugins.windows.ntpclient.NTPClientPlugin',
        'cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin',
        'cloudbaseinit.plugins.windows.createuser.CreateUserPlugin',
        'cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin',
        'cloudbaseinit.plugins.windows.licensing.WindowsLicensingPlugin',
        'cloudbaseinit.plugins.common.sshpublickeys.SetUserSSHPublicKeysPlugin',
        'cloudbaseinit.plugins.windows.extendvolumes.ExtendVolumesPlugin',
        'cloudbaseinit.plugins.common.userdata.UserDataPlugin',
        'cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin',
        'cloudbaseinit.plugins.windows.winrmlistener.ConfigWinRMListenerPlugin',
        'cloudbaseinit.plugins.windows.winrmcertificateauth.ConfigWinRMCertificateAuthPlugin',
        'cloudbaseinit.plugins.common.localscripts.LocalScriptsPlugin'
    ) -join ','

    $metadataServices = @('cloudbaseinit.metadata.services.cloudstack.CloudStack') -join ','

    $conf = @"
[DEFAULT]
username = $CloudUser
inject_user_password = true
first_logon_behaviour = no
metadata_services = $metadataServices
plugins = $plugins
process_userdata = true
service_change_startup_type = true
"@
    $conf | Out-File -FilePath $cbConf -Encoding ASCII -Force

    Ensure-ServiceAutoStart -Name 'cloudbase-init' -DependsOn @('nsi','Tcpip')
    cmd /c 'sc.exe failure "cloudbase-init" reset= 86400 actions= restart/5000/restart/5000/restart/5000' | Out-Null
    cmd /c 'sc.exe failureflag "cloudbase-init" 1' | Out-Null
}

# ------------------------ Unattend.xml for Sysprep ----------------------------

function Write-Unattend {
    Step 'Write C:\unattend.xml (preserve VirtIO drivers)'
    $cpuArch = if ([Environment]::Is64BitOperatingSystem) {'amd64'} else {'x86'}
    $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="generalize">
    <component name="Microsoft-Windows-PnpSysprep"
               processorArchitecture="$cpuArch"
               publicKeyToken="31bf3856ad364e35"
               language="neutral"
               versionScope="nonSxS"
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <PersistAllDeviceInstalls>true</PersistAllDeviceInstalls>
      <DoNotCleanUpNonPresentDevices>true</DoNotCleanUpNonPresentDevices>
    </component>
  </settings>
</unattend>
"@
    $path = 'C:\unattend.xml'
    $xml | Out-File -FilePath $path -Encoding UTF8 -Force
}




# ------------------------ Unattend Validation ---------------------------------
function Validate-Unattend {
    Step 'Validation: Unattend XML structure'
    $path = 'C:\unattend.xml'
    if (-not (Test-Path $path)) {
        Write-Host "unattend.xml missing at $path" -ForegroundColor Red
        return
    }
    try {
        [xml]$doc = Get-Content $path -Raw -Encoding UTF8
        $ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
        $ns.AddNamespace('u','urn:schemas-microsoft-com:unattend')
        $ns.AddNamespace('wcm','http://schemas.microsoft.com/WMIConfig/2002/State')
        $node = $doc.SelectSingleNode('/u:unattend/u:settings[@pass="generalize"]/u:component[@name="Microsoft-Windows-PnpSysprep"]', $ns)
        if ($null -eq $node) {
            Write-Host "PnPSysprep component not found under generalize!" -ForegroundColor Red
        } else {
            Write-Host "PnPSysprep component present under generalize." -ForegroundColor Green
        }
    } catch {
        Write-Host "Failed to parse unattend.xml as XML: $($_.Exception.Message)" -ForegroundColor Red
    }
}
# ------------------------ Validation & Summary --------------------------------
function Validate-Unattend`n    Validate-PostSetup {
    Step 'Validation: RDP service and firewall'
    $rdpSvc = Get-Service TermService -ErrorAction SilentlyContinue
    if ($rdpSvc) {
        "{0} - Status: {1} - StartType: {2}" -f $rdpSvc.Name, $rdpSvc.Status, $rdpSvc.StartType | Write-Host
        try {
            $rdpRules = Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue | Select-Object Name,Enabled
            if ($rdpRules) { $rdpRules | Format-Table | Out-String | Write-Host }
            else {
                $rdpRules = Get-NetFirewallRule -Name 'RemoteDesktop-UserMode-In-TCP','RemoteDesktop-UserMode-In-UDP' -ErrorAction SilentlyContinue | Select-Object Name,Enabled
                if ($rdpRules) { $rdpRules | Format-Table | Out-String | Write-Host }
            }
        } catch {}
        try {
            $deny = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections').fDenyTSConnections
            $nla  = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication').UserAuthentication
            "RDP Enabled (fDenyTSConnections=0)? {0}; NLA (UserAuthentication=1)? {1}" -f ($deny -eq 0), ($nla -eq 1) | Write-Host
        } catch {}
    } else {
        Write-Host "TermService not present; RDP service validation skipped." -ForegroundColor DarkYellow
    }

    Step 'Validation: Cloudbase-Init service & config'
    $cb = Get-Service cloudbase-init -ErrorAction SilentlyContinue
    if ($cb) {
        "{0} - Status: {1} - StartType: {2}" -f $cb.Name, $cb.Status, $cb.StartType | Write-Host
    } else {
        Write-Host "cloudbase-init service not found!" -ForegroundColor Red
    }
    $cbConf = Join-Path "${env:ProgramFiles}\Cloudbase Solutions\Cloudbase-Init\conf" "cloudbase-init.conf"
    "cloudbase-init.conf exists? {0}" -f (Test-Path $cbConf) | Write-Host

    Step 'Validation: QEMU Guest Agent (optional)'
    $ga = @()
    $ga += Get-Service -Name 'QEMU-GA' -ErrorAction SilentlyContinue
    $ga += Get-Service -Name 'qemu-ga' -ErrorAction SilentlyContinue
    if (-not $ga) {
        $ga += Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'QEMU.*Agent' -or $_.Name -match 'qemu' }
    }
    if ($ga) {
        $ga | Select-Object Name,Status,StartType | Format-Table | Out-String | Write-Host
    } else {
        Write-Host "QEMU guest agent service not detected (this is OK if not installed by your MSI)." -ForegroundColor DarkYellow
    }

    Step 'Validation: Sysprep file & network wait policy'
    "Unattend.xml exists? {0}" -f (Test-Path 'C:\unattend.xml') | Write-Host
    try {
        $sync = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'SyncForegroundPolicy' -ErrorAction SilentlyContinue).SyncForegroundPolicy
        "SyncForegroundPolicy=1? {0}" -f ($sync -eq 1) | Write-Host
    } catch {}

    Step 'Validation: Pagefile automatic'
    try {
        $cs = Get-WmiObject -Class Win32_ComputerSystem
        "AutomaticManagedPagefile? {0}" -f ($cs.AutomaticManagedPagefile -eq $true) | Write-Host
    } catch {}
}
# ------------------------ Compatibility nudges --------------------------------
function Prepare-LocalAccount {
    Step "Ensure '$CloudUser' exists and is enabled"
    try {
        if ($CloudUser -ne 'Administrator') {
            $u = Get-LocalUser -Name $CloudUser -ErrorAction SilentlyContinue
            if (-not $u) {
                New-LocalUser -Name $CloudUser -NoPassword -AccountNeverExpires -UserMayNotChangePassword:$false -ErrorAction Stop | Out-Null
            } else {
                try { Enable-LocalUser -Name $CloudUser -ErrorAction SilentlyContinue } catch {}
            }
            try {
                Add-LocalGroupMember -Group 'Administrators' -Member $CloudUser -ErrorAction SilentlyContinue
                Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $CloudUser -ErrorAction SilentlyContinue
            } catch {}
        }
    } catch {
        Write-Verbose "Local account handling skipped or failed for '$CloudUser'. Continuing."
    }
}

# ------------------------ Main ------------------------------------------------
try {
    Step 'Start: CloudStack Windows Template Prep'
    Optimize-OS
    Fix-Pagefile
    Prepare-LocalAccount
    Install-VirtIO
    Install-CloudbaseInit
    Write-Unattend
    Safe-Cleanup

    Validate-PostSetup

    Step 'Done. Next steps:'
    Write-Host @"
1) Optional: re-run with -CloudUser 'YourAdminUser' to target a different account.
2) Seal the image (do not log in after sysprep):
   C:\Windows\System32\Sysprep\sysprep.exe /generalize /oobe /shutdown /unattend:C:\unattend.xml
3) Register as a template in CloudStack and set "Password Enabled" = Yes.
"@ -ForegroundColor Yellow
}
catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    exit 1
}
finally {
    if ($transcriptStarted) { try { Stop-Transcript | Out-Null } catch {} }
    Write-Host "Log saved to: $log" -ForegroundColor Gray
}
