#requires -Version 5.1
<#
    CloudStack Windows Template Prep (Server 2016 → 2025)
    ----------------------------------------------------
    Run as: Administrator (auto-elevates if needed)
    Safe to re-run. Logs to C:\cloudstack-prep.log

    Key goals:
      • Cloudbase-Init service starts at boot (pre-logon), restart-on-failure
      • RDP enabled with NLA + firewall opened (without altering service dependencies)
      • VirtIO Guest Tools installed; QEMU-GA started
      • OS waits for network at startup
      • Unattend.xml persists drivers through sysprep
#>

# ------------------------ Parameters (must be first) ---------------------------
param(
    [string]$CloudUser = 'Administrator',     # account to receive password injection
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
    if ($PSBoundParameters.ContainsKey('CloudUser')) { $argList += @('-CloudUser', $CloudUser) }
    if ($PSBoundParameters.ContainsKey('SkipVirtIO')) { $argList += '-SkipVirtIO' }
    if ($PSBoundParameters.ContainsKey('SkipCloudbaseInit')) { $argList += '-SkipCloudbaseInit' }
    $psi = New-Object System.Diagnostics.ProcessStartInfo "powershell"
    $psi.Arguments = $argList -join ' '
    $psi.Verb = "RunAs"
    try {
        $p = [System.Diagnostics.Process]::Start($psi)
        if ($p) { exit }
    } catch {
        Write-Error "User declined elevation. Exiting."
        exit 1
    }
}

# ------------------------ Hardening defaults ----------------------------------
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$log = 'C:\cloudstack-prep.log'
$transcriptStarted = $false
try {
    Start-Transcript -Path $log -Append | Out-Null
    $transcriptStarted = $true
} catch {
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    try {
        Start-Transcript -Path "C:\cloudstack-prep_$timestamp.log" -Append | Out-Null
        $transcriptStarted = $true
    } catch {}
}

function Step([string]$m) { Write-Host ">> $m" -ForegroundColor Cyan }
try { Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue } catch {}

# ------------------------ Helpers ---------------------------------------------
function Ensure-ServiceAutoStart {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [string[]]$DependsOn
    )
    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop
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
    } catch {
        Write-Warning "Service $Name not found or could not be configured: $($_.Exception.Message)"
    }
}

# ------------------------ OS Optimisation -------------------------------------
function Optimize-OS {
    Step 'Enable RDP + NLA and open firewall'
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -PropertyType DWord -Force | Out-Null

    # Keep TermService defaults; do NOT alter dependencies to avoid platform quirks
    try { & sc.exe config TermService start= auto | Out-Null } catch {}
    try { Start-Service -Name TermService -ErrorAction SilentlyContinue } catch {}

    # Firewall: first try DisplayGroup, then exact rule names (TCP/UDP)
    $enabled = $false
    try { Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction Stop | Out-Null; $enabled = $true } catch {}
    if (-not $enabled) {
        foreach ($rule in @('RemoteDesktop-UserMode-In-TCP','RemoteDesktop-UserMode-In-UDP')) {
            try { Enable-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue | Out-Null } catch {}
        }
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
    Step 'Install VirtIO Guest Tools'

    # VirtIO MSI uses x64/x86 naming, NOT amd64.
    $arch = if ([Environment]::Is64BitOperatingSystem) {'x64'} else {'x86'}
    $msiName = "virtio-win-gt-$arch.msi"
    $msiPath = Join-Path $env:TEMP $msiName

    $urls = @(
        "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/$msiName",
        "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/$msiName"
    )

    $downloaded = $false
    foreach ($u in $urls) {
        try {
            Step "Downloading VirtIO from: $u"
            Invoke-WebRequest -Uri $u -OutFile $msiPath -UseBasicParsing -ErrorAction Stop
            $downloaded = $true
            break
        } catch {
            Write-Warning "Download failed: $u (`$($_.Exception.Message)`)"
        }
    }
    if (-not $downloaded) {
        throw "VirtIO MSI not downloaded from any source. Tried: $($urls -join ', ')"
    }

    $args = "/i `"$msiPath`" /qn /norestart"
    $p = Start-Process -FilePath msiexec.exe -ArgumentList $args -PassThru -Wait
    if ($p.ExitCode -ne 0) { throw "VirtIO installer exit code: $($p.ExitCode)" }

    foreach ($svcName in @('QEMU-GA','qemu-ga')) {
        Ensure-ServiceAutoStart -Name $svcName -DependsOn @('nsi','Tcpip')
    }
}

# ------------------------ Cloudbase-Init --------------------------------------
function Install-CloudbaseInit {
    if ($SkipCloudbaseInit) { Step 'Skip Cloudbase-Init (requested)'; return }

    Step 'Install Cloudbase-Init (stable)'
    $arch = if ([Environment]::Is64BitOperatingSystem) {'x64'} else {'x86'}
    $msiPath = "$env:TEMP\CloudbaseInit_$arch.msi"

    $urls = @(
        "https://github.com/cloudbase/cloudbase-init/releases/latest/download/CloudbaseInitSetup_$arch.msi",
        "https://www.cloudbase.it/downloads/CloudbaseInitSetup_Stable_$arch.msi"
    )

    $downloaded = $false
    foreach ($u in $urls) {
        try {
            Step "Downloading: $u"
            Invoke-WebRequest -Uri $u -OutFile $msiPath -UseBasicParsing -ErrorAction Stop
            $downloaded = $true; break
        } catch {
            Write-Warning "Download failed: $u"
        }
    }
    if (-not $downloaded) { throw "Could not download Cloudbase-Init MSI." }

    # Install as service, do not run sysprep automatically
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

    # Ensure the service is Automatic, started, with dependency on basic network
    Ensure-ServiceAutoStart -Name 'cloudbase-init' -DependsOn @('nsi','Tcpip')
    # Aggressive service recovery
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
               versionScope="nonSxS"
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <PersistAllDeviceInstalls>true</PersistAllDeviceInstalls>
    </component>
  </settings>
</unattend>
"@
    $xml | Out-File -FilePath 'C:\unattend.xml' -Encoding ASCII -Force
}

# ------------------------ Compatibility nudges --------------------------------
function Prepare-LocalAccount {
    Step "Ensure '$CloudUser' exists and is enabled"
    try {
        # Skip creation if CloudUser is the built-in Administrator
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
