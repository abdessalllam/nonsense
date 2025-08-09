#requires -Version 5.1
<#
    CloudStack Windows Template Prep (Server 2016 → 2025) — v13
    -----------------------------------------------------------
    • Forces 64‑bit, elevated PowerShell (self‑relaunch)
    • Installs Cloudbase‑Init (as LocalSystem) and repairs broken service registrations
    • Installs VirtIO guest tools silently (ADDLOCAL=ALL), with pnputil fallback and QEMU GA from ISO if needed
    • Enables RDP + NLA, opens firewall, waits for network at startup
    • Writes a safe unattend.xml to preserve drivers through sysprep
    • Validates everything at the end; logs to C:\cloudstack-prep.log

    Parameters:
      -CloudUser 'Administrator'                  # target account for metadata password
      -CloudbaseInitVersion '1.1.6'               # versioned GitHub release
      -CloudbaseInitMsiPath 'C:\path\CloudbaseInitSetup_1_1_6_x64.msi'   # offline
      -VirtIOMsiPath 'C:\path\virtio-win-gt-x64.msi'                     # offline
      -VirtIOIsoDrive 'E:'                        # mounted virtio ISO for pnputil & GA MSI fallback
      -SkipVirtIO, -SkipCloudbaseInit
#>

param(
    [string]$CloudUser = 'Administrator',
    [string]$CloudbaseInitVersion = '1.1.6',
    [string]$CloudbaseInitMsiPath = '',
    [string]$VirtIOMsiPath = '',
    [string]$VirtIOIsoDrive = '',
    [switch]$SkipVirtIO,
    [switch]$SkipCloudbaseInit
)

# ------------------------ Admin & 64-bit enforcement ---------------------------
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Assert-Admin {
    if (-not (Test-IsAdmin)) { throw "This script must run as Administrator." }
}
# Relaunch as 64-bit, elevated PowerShell if needed
$need64 = [Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess
$needAdmin = -not (Test-IsAdmin)
if ($need64 -or $needAdmin) {
    $hostPs = if ($need64) { "$env:WINDIR\sysnative\WindowsPowerShell\v1.0\powershell.exe" } else { "powershell.exe" }
    Write-Host "Relaunching as $([bool]$need64 ? '64-bit ' : '')Administrator..." -ForegroundColor Yellow
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
    $psi = New-Object System.Diagnostics.ProcessStartInfo $hostPs
    $psi.Arguments = ($argList -join ' ')
    $psi.Verb = "RunAs"
    try { [System.Diagnostics.Process]::Start($psi) | Out-Null; exit } catch { throw "Elevation/64-bit relaunch cancelled." }
}
Assert-Admin
$Is64OS = [Environment]::Is64BitOperatingSystem
$ProgramFilesPreferred = if ($Is64OS) { $env:ProgramW6432 } else { $env:ProgramFiles }
$Msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
$Pnputil = Join-Path $env:SystemRoot 'System32\pnputil.exe'

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
        try { Set-Service -Name $Name -StartupType Automatic } catch {}
        try { Start-Service -Name $Name -ErrorAction SilentlyContinue } catch {}
        $reg = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
        try { New-Item -Path $reg -Force | Out-Null; New-ItemProperty -Path $reg -Name 'DelayedAutoStart' -Value 0 -PropertyType DWord -Force | Out-Null } catch {}
        return $true
    }
    return $false
}
function Ensure-ServiceAutoStart {
    param([Parameter(Mandatory)][string]$Name,[string[]]$DependsOn)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { return }
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
    if (Try-StartService -Name 'TermService') {
        $enabled = $false
        try { Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction Stop | Out-Null; $enabled = $true } catch {}
        if (-not $enabled) {
            foreach ($rule in @('RemoteDesktop-UserMode-In-TCP','RemoteDesktop-UserMode-In-UDP')) {
                try { Enable-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue | Out-Null } catch {}
            }
            try { & netsh advfirewall firewall set rule group="remote desktop" new enable=Yes | Out-Null } catch {}
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
    if ($cs.AutomaticManagedPagefile -ne $true) { $cs.AutomaticManagedPagefile = $true; $cs.Put() | Out-Null }
}

# ------------------------ Cleanup ---------------------------------------------
function Safe-Cleanup {
    Step 'Clean TEMP and Windows Update cache'
    $targets = @("$env:TEMP","$env:WINDIR\Temp","C:\Windows\SoftwareDistribution\Download")
    foreach ($t in $targets) { if (Test-Path $t) {
        Get-ChildItem -Path $t -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }}

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
            try { Step "Downloading VirtIO from: $u"; Invoke-WebRequest -Uri $u -OutFile $msiPath -UseBasicParsing -ErrorAction Stop; $downloaded = $true; break } catch { Write-Verbose "VirtIO download failed: $u" }
        }
        if (-not $downloaded) { throw "VirtIO MSI not downloaded from any source." }
    }

    if (-not (Test-Path $msiPath)) { throw "VirtIO MSI not found at $msiPath" }
    $args = "/i `"$msiPath`" /qn /norestart ADDLOCAL=ALL /l*v C:\virtio-gt-install.log"
    $p = Start-Process -FilePath $Msiexec -ArgumentList $args -PassThru -Wait
    if ($p.ExitCode -ne 0) { throw "VirtIO installer exit code: $($p.ExitCode)" }

    # Stage drivers with pnputil from ISO if requested & still not visible
    $hasRedHatDrivers = $false
    try {
        $drivers = Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DriverProviderName -like '*Red Hat*' -or $_.Manufacturer -like '*Red Hat*' }
        if ($drivers) { $hasRedHatDrivers = $true }
    } catch {}

    if (-not $hasRedHatDrivers -and $VirtIOIsoDrive) {
        Step "Staging VirtIO drivers via pnputil from $VirtIOIsoDrive (fallback)"
        $infGlob = Join-Path "$VirtIOIsoDrive\" "*.inf"
        try {
            & $Pnputil /add-driver "$infGlob" /subdirs /install | Out-Null
            $drivers = Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DriverProviderName -like '*Red Hat*' -or $_.Manufacturer -like '*Red Hat*' }
            if ($drivers) { $hasRedHatDrivers = $true }
        } catch { Write-Verbose "pnputil staging failed: $($_.Exception.Message)" }
    }

    # QEMU Guest Agent: try to start if installed; otherwise attempt from ISO if present
    $gaSvcNames = @('QEMU-GA','qemu-ga')
    $gaFound = $false
    foreach ($svc in $gaSvcNames) { if (Try-StartService -Name $svc) { $gaFound = $true } }

    if (-not $gaFound -and $VirtIOIsoDrive) {
        $gaMsi = Join-Path "$VirtIOIsoDrive\guest-agent" "qemu-ga-x86_64.msi"
        if (Test-Path $gaMsi) {
            Step "Installing QEMU Guest Agent from $gaMsi"
            $gaArgs = "/i `"$gaMsi`" /qn /norestart /l*v C:\qemu-ga-install.log"
            $gp = Start-Process -FilePath $Msiexec -ArgumentList $gaArgs -PassThru -Wait
            if ($gp.ExitCode -eq 0) { foreach ($svc in $gaSvcNames) { Try-StartService -Name $svc | Out-Null }; $gaFound = $true }
        }
    }
}

# ------------------------ Cloudbase-Init Repair --------------------------------
function Repair-CloudbaseInitService {
    param([string]$MsiPath,[string]$Version = '1.1.6')
    Step 'Repair: verifying Cloudbase-Init service registration'
    $svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\cloudbase-init'
    $base   = (Join-Path $ProgramFilesPreferred "Cloudbase Solutions\Cloudbase-Init")
    $svc    = Get-Service -Name 'cloudbase-init' -ErrorAction SilentlyContinue
    $props  = Get-ItemProperty -Path $svcKey -ErrorAction SilentlyContinue
    $img    = $null; if ($props) { $img = $props.ImagePath }
    $exe1   = Join-Path $base 'Python\Scripts\cloudbase-init.exe'
    $exe2   = Join-Path $base 'bin\OpenStackService.exe'
    $haveBin= (Test-Path $exe1) -or (Test-Path $exe2)

    $broken = $false
    if (-not $props) { $broken = $true }
    elseif (-not $haveBin)   { $broken = $true }
    elseif ([string]::IsNullOrWhiteSpace($img)) { $broken = $true }

    if ($broken) {
        Step 'Repair: cloudbase-init service looks broken → removing and reinstalling'
        try { sc.exe stop cloudbase-init | Out-Null } catch {}
        try { sc.exe delete cloudbase-init | Out-Null } catch {}

        $arch = if ([Environment]::Is64BitOperatingSystem) {'x64'} else {'x86'}
        $msi = $MsiPath
        if (-not $msi) {
            $vUnderscore = ($Version -replace '\.','_')
            $name = "CloudbaseInitSetup_{0}_{1}.msi" -f $vUnderscore, $arch
            $msi = Join-Path $env:TEMP $name
            $url = "https://github.com/cloudbase/cloudbase-init/releases/download/$Version/$name"
            Step "Repair: downloading Cloudbase-Init $Version from $url"
            Invoke-WebRequest -Uri $url -OutFile $msi -UseBasicParsing -ErrorAction Stop
        }
        if (-not (Test-Path $msi)) { throw "Repair failed: MSI not found at $msi" }

        $args = "/i `"$msi`" /qn /norestart RUN_CLOUDBASEINIT_SERVICE=1 SYSPREP_DISABLED=1 RUN_SERVICE_AS_LOCAL_SYSTEM=1 /l*v C:\cloudbase-init-install.log"
        $proc = Start-Process -FilePath $Msiexec -ArgumentList $args -PassThru -Wait
        if ($proc.ExitCode -ne 0) { throw "Repair failed: Cloudbase-Init installer exit code $($proc.ExitCode)" }
    }

    Ensure-ServiceAutoStart -Name 'cloudbase-init' -DependsOn @('nsi','Tcpip')
    cmd /c 'sc.exe failure "cloudbase-init" reset= 86400 actions= restart/5000/restart/5000/restart/5000' | Out-Null
    cmd /c 'sc.exe failureflag "cloudbase-init" 1' | Out-Null
    try { Start-Service -Name 'cloudbase-init' -ErrorAction SilentlyContinue } catch {}

    try {
        $props  = Get-ItemProperty -Path $svcKey -ErrorAction SilentlyContinue
        $img    = if ($props) { $props.ImagePath } else { $null }
        if ($img) { Write-Host ("cloudbase-init ImagePath: {0}" -f $img) }
        $svc    = Get-Service -Name 'cloudbase-init' -ErrorAction SilentlyContinue
        if ($svc) { "{0} - Status: {1} - StartType: {2}" -f $svc.Name, $svc.Status, $svc.StartType | Write-Host }
    } catch {}
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
        try { Invoke-WebRequest -Uri $url -OutFile $msiPath -UseBasicParsing -ErrorAction Stop } catch { throw "Failed to download Cloudbase-Init from $url : $($_.Exception.Message)" }
    }
    if (-not (Test-Path $msiPath)) { throw "Cloudbase-Init MSI not found at $msiPath" }

    $cbArgs = "/i `"$msiPath`" /qn /norestart RUN_CLOUDBASEINIT_SERVICE=1 SYSPREP_DISABLED=1 RUN_SERVICE_AS_LOCAL_SYSTEM=1 /l*v C:\cloudbase-init-install.log"
    $proc = Start-Process -FilePath $Msiexec -ArgumentList $cbArgs -PassThru -Wait
    if ($proc.ExitCode -ne 0) { throw "Cloudbase-Init installer exit code: $($proc.ExitCode)" }

    Step 'Configure Cloudbase-Init for CloudStack password injection'
    $cbRoot   = (Join-Path $ProgramFilesPreferred "Cloudbase Solutions\Cloudbase-Init")
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

    # Final check & repair if needed
    $svc = Get-Service -Name 'cloudbase-init' -ErrorAction SilentlyContinue
    $startType = $null; if ($svc) { $startType = $svc.StartType }
    $svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\cloudbase-init'
    $imagePath = (Get-ItemProperty -Path $svcKey -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
    $base = (Join-Path $ProgramFilesPreferred "Cloudbase Solutions\Cloudbase-Init")
    $exe1 = Join-Path $base 'Python\Scripts\cloudbase-init.exe'
    $exe2 = Join-Path $base 'bin\OpenStackService.exe'
    $looksBroken = (-not $svc) -or (-not $imagePath) -or ((-not (Test-Path $exe1)) -and (-not (Test-Path $exe2)))
    if ($looksBroken -or -not $startType) {
        Step 'cloudbase-init service appears mis-registered; attempting repair'
        Repair-CloudbaseInitService -MsiPath $msiPath -Version $CloudbaseInitVersion
    }
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
    if (-not (Test-Path $path)) { Write-Host "unattend.xml missing at $path" -ForegroundColor Red; return }
    try {
        [xml]$doc = Get-Content $path -Raw -Encoding UTF8
        $ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
        $ns.AddNamespace('u','urn:schemas-microsoft-com:unattend')
        $ns.AddNamespace('wcm','http://schemas.microsoft.com/WMIConfig/2002/State')
        $node = $doc.SelectSingleNode('/u:unattend/u:settings[@pass="generalize"]/u:component[@name="Microsoft-Windows-PnpSysprep"]', $ns)
        if ($null -eq $node) { Write-Host "PnPSysprep component not found under generalize!" -ForegroundColor Red } else { Write-Host "PnPSysprep component present under generalize." -ForegroundColor Green }
    } catch { Write-Host "Failed to parse unattend.xml as XML: $($_.Exception.Message)" -ForegroundColor Red }
}

# ------------------------ Compatibility nudges --------------------------------
function Prepare-LocalAccount {
    Step "Ensure '$CloudUser' exists and is enabled"
    try {
        if ($CloudUser -ne 'Administrator') {
            $u = Get-LocalUser -Name $CloudUser -ErrorAction SilentlyContinue
            if (-not $u) { New-LocalUser -Name $CloudUser -NoPassword -AccountNeverExpires -UserMayNotChangePassword:$false -ErrorAction Stop | Out-Null }
            else { try { Enable-LocalUser -Name $CloudUser -ErrorAction SilentlyContinue } catch {} }
            try {
                Add-LocalGroupMember -Group 'Administrators' -Member $CloudUser -ErrorAction SilentlyContinue
                Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $CloudUser -ErrorAction SilentlyContinue
            } catch {}
        }
    } catch { Write-Verbose "Local account handling skipped or failed for '$CloudUser'. Continuing." }
}

# ------------------------ Validation & Summary --------------------------------
function Validate-PostSetup {
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
    } else { Write-Host "TermService not present; RDP service validation skipped." -ForegroundColor DarkYellow }

    Step 'Validation: Cloudbase-Init service & config'
    try { $img=(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\cloudbase-init' -Name ImagePath -ErrorAction SilentlyContinue).ImagePath; if($img){ "ImagePath: $img" | Write-Host } } catch {}
    $cb = Get-Service cloudbase-init -ErrorAction SilentlyContinue
    if ($cb) { "{0} - Status: {1} - StartType: {2}" -f $cb.Name, $cb.Status, $cb.StartType | Write-Host } else { Write-Host "cloudbase-init service not found!" -ForegroundColor Red }
    $cbConf = Join-Path (Join-Path $ProgramFilesPreferred "Cloudbase Solutions\Cloudbase-Init\conf") "cloudbase-init.conf"
    "cloudbase-init.conf exists? {0}" -f (Test-Path $cbConf) | Write-Host

    Step 'Validation: QEMU Guest Agent (optional)'
    $ga = @(); $ga += Get-Service -Name 'QEMU-GA' -ErrorAction SilentlyContinue; $ga += Get-Service -Name 'qemu-ga' -ErrorAction SilentlyContinue
    if (-not $ga) { $ga += Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'QEMU.*Agent' -or $_.Name -match 'qemu' } }
    if ($ga) {
        $ga | ForEach-Object { Ensure-ServiceAutoStart -Name $_.Name -DependsOn @('nsi','Tcpip') }
        $ga | Select-Object Name,Status,StartType | Format-Table | Out-String | Write-Host
    } else { Write-Host "QEMU guest agent service not detected (this is OK if not installed by your MSI)." -ForegroundColor DarkYellow }

    Step 'Validation: VirtIO driver store & services'
    try {
        $drivers = Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DriverProviderName -like '*Red Hat*' -or $_.Manufacturer -like '*Red Hat*' } | Select-Object DeviceName, DriverVersion, DriverProviderName
        if ($drivers) { "Red Hat drivers in store:" | Write-Host; $drivers | Sort-Object DeviceName | Format-Table | Out-String | Write-Host }
        else { Write-Host "No Red Hat (VirtIO) drivers found in driver store. They may install only when matching hardware is present." -ForegroundColor DarkYellow }
    } catch {}
    'NetKVM','vioscsi','viostor','vioserial','vioinput','viorng','qemufwcfg','qemupciserial','pvpanic' | ForEach-Object {
        $exists = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$_"; "{0} service present? {1}" -f $_, $exists | Write-Host
    }

    Step 'Validation: Sysprep file & network wait policy'
    "Unattend.xml exists? {0}" -f (Test-Path 'C:\unattend.xml') | Write-Host
    try { $sync = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'SyncForegroundPolicy' -ErrorAction SilentlyContinue).SyncForegroundPolicy; "SyncForegroundPolicy=1? {0}" -f ($sync -eq 1) | Write-Host } catch {}

    Step 'Validation: Pagefile automatic'
    try { $cs = Get-WmiObject -Class Win32_ComputerSystem; "AutomaticManagedPagefile? {0}" -f ($cs.AutomaticManagedPagefile -eq $true) | Write-Host } catch {}
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
    Validate-Unattend
    Safe-Cleanup

    Step 'Done. Next steps:'
    Write-Host ( @"
1) Optional: re-run with -CloudUser 'YourAdminUser' to target a different account.
2) Seal the image (do not log in after sysprep):
   C:\Windows\System32\Sysprep\sysprep.exe /generalize /oobe /shutdown /unattend:C:\unattend.xml
3) Register as a template in CloudStack and set "Password Enabled" = Yes.
"@
    ) -ForegroundColor Yellow
    Validate-PostSetup
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
