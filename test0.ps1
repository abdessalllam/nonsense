#requires -RunAsAdministrator
#==============================================================================
#  prepare-cloudstack.ps1
#------------------------------------------------------------------------------
#  Pre-configure a Windows Server (2016 → 2025) guest for Apache CloudStack:
#    • Balanced power plan
#    • RDP + NLA enabled, firewall rule opened
#    • Basic TCP tweaks   (rss / autotune / chimney) – silently ignored if OS
#      doesn’t support a flag
#    • Pagefile set to “automatic” on C:
#    • Cleans TEMP folders, Windows-Update cache, WinSxS (newer builds) and
#      clears event-logs (protected logs skipped)
#    • Installs VirtIO Guest-Tools 0.1.271   (x86 / x64, idempotent)
#    • Installs Cloudbase-Init (cloud-init for Windows) and configures it for
#      CloudStack password injection
#    • Writes C:\unattend.xml so VirtIO drivers survive sysprep /generalize
#    • Full transcript: C:\cloudstack-prep.log
#==============================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ───────────────────────── TRANSCRIPT ─────────────────────────
$LogPath = 'C:\cloudstack-prep.log'
try   { Start-Transcript -Path $LogPath -Append }
catch {
    $LogPath = "C:\cloudstack-prep_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
    Start-Transcript -Path $LogPath -Append
}

function Write-Step {
    param([string]$Message)
    Write-Host "`n>> $Message"
}

# ─────────────────────── 1.  OS TUNING ───────────────────────
function Set-PowerPlanBalanced {
    Write-Step 'Setting Balanced power plan'
    powercfg /setactive SCHEME_BALANCED | Out-Null
}

function Enable-RDP {
    Write-Step 'Enabling RDP (with NLA) + firewall'
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    Set-ItemProperty -Path $ts -Name fDenyTSConnections -Value 0
    Set-ItemProperty -Path "$ts\WinStations\RDP-Tcp" -Name UserAuthentication -Value 1
    Set-Service TermService -StartupType Automatic
    if ((Get-Service TermService).Status -ne 'Running') { Start-Service TermService }
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
}

function Tune-TCP {
    Write-Step 'Applying TCP flags (best-effort)'
    foreach ($flag in 'rss=enabled','autotuninglevel=normal','chimney=disabled') {
        cmd /c "netsh interface tcp set global $flag >nul 2>nul"
    }
}

# ─────────────────────── 2.  PAGEFILE ────────────────────────
function Set-AutomaticPagefile {
    Write-Step 'Pagefile → automatic on C:'
    if (Get-Command wmic -ErrorAction SilentlyContinue) {
        wmic computersystem where name="%COMPUTERNAME%" set AutomaticManagedPagefile=True  >$null 2>&1
        wmic pagefileset   where "name!='C:\\\\pagefile.sys'" delete                        >$null 2>&1
    }
    else {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        if (-not $cs.AutomaticManagedPagefile) {
            Set-CimInstance -InputObject $cs -Property @{ AutomaticManagedPagefile = $true }
        }
    }
}

# ─────────────────────── 3.  CLEAN-UP ────────────────────────
function Clear-Temp {
    Write-Step 'Clearing TEMP folders'
    foreach ($p in "$env:TEMP",'C:\Windows\Temp') {
        Get-ChildItem $p -Recurse -Force -ErrorAction SilentlyContinue |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Clear-WUCache {
    Write-Step 'Flushing Windows-Update cache'
    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force 'C:\Windows\SoftwareDistribution\Download\*' -ErrorAction SilentlyContinue
    Start-Service wuauserv    -ErrorAction SilentlyContinue
}

function Trim-WinSxS {
    if ([Environment]::OSVersion.Version.Build -ge 14393) {   # Server 2016+
        Write-Step 'Cleaning WinSxS store'
        Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null
    }
}

function Clear-EventLogs {
    Write-Step 'Clearing event-logs (protected logs skipped)'
    foreach ($name in & wevtutil el) { & wevtutil cl "$name" 1>$null 2>$null }
}

# ───────────── 4.  VIRTIO 0.1.271 (idempotent) ──────────────
function Install-Virtio {
    $already = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue |
               Where-Object { $_.DisplayName -match 'VirtIO.*Guest.*Tools' }
    if ($already) { Write-Step 'VirtIO Guest-Tools already installed – skipping'; return }

    Write-Step 'Downloading VirtIO Guest-Tools 0.1.271'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $arch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    $msi  = "$env:TEMP\virtio-gt-$arch.msi"
    $url1 = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.271-1/virtio-win-gt-$arch.msi"
    $url2 = "https://fedora-virt.repo.nfrance.com/virtio-win/direct-downloads/stable-virtio/virtio-win-gt-$arch.msi"

    try   { Invoke-WebRequest $url1 -OutFile $msi -UseBasicParsing -EA Stop }
    catch { Write-Step 'Primary mirror failed – using mirror 2'
            Invoke-WebRequest $url2 -OutFile $msi -UseBasicParsing }

    Write-Step 'Installing VirtIO Guest-Tools'
    $rc = (Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -Wait -PassThru).ExitCode
    if ($rc) { throw "VirtIO installer exit-code $rc" }
}

# ───────────── 5.  CLOUDBASE-INIT (cloud-init) ──────────────
function Install-CloudbaseInit {
    if (Get-Service cloudbase-init -EA SilentlyContinue) {
        Write-Step 'Cloudbase-Init already installed – skipping'; return
    }

    Write-Step 'Downloading Cloudbase-Init'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $arch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    $msi  = "$env:TEMP\cloudbase-init-$arch.msi"
    $u1   = "https://www.cloudbase.it/downloads/CloudbaseInitSetup_Stable_${arch}.msi"
    $u2   = "https://github.com/cloudbase/cloudbase-init/releases/latest/download/CloudbaseInitSetup_${arch}.msi"

    try   { Invoke-WebRequest $u1 -OutFile $msi -UseBasicParsing -EA Stop }
    catch { Write-Step 'Primary mirror failed – using GitHub'
            Invoke-WebRequest $u2 -OutFile $msi -UseBasicParsing }

    Write-Step 'Installing Cloudbase-Init'
    $rc = (Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart RUN_CLOUDBASEINIT_SERVICE=1 SYSPREP_DISABLED=1" `
          -Wait -PassThru).ExitCode
    if ($rc) { throw "Cloudbase-Init installer exit-code $rc" }

    Write-Step 'Configuring Cloudbase-Init for CloudStack'
    $cfg = "$env:ProgramFiles\Cloudbase Solutions\Cloudbase-Init\conf\cloudbase-init.conf"
@'
[DEFAULT]
username              = Administrator
inject_user_password  = true
first_logon_behaviour = no
metadata_services     = cloudbaseinit.metadata.services.cloudstack.CloudStack
plugins               = cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin,
                        cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin,
                        cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin,
                        cloudbaseinit.plugins.common.userdata.UserDataPlugin
'@ | Out-File $cfg -Encoding ASCII -Force

    Set-Service cloudbase-init -StartupType Automatic
    Start-Service cloudbase-init
}

# ───────────── 6.  unattend.xml (keep VirtIO) ──────────────
function Write-UnattendXml {
    Write-Step 'Writing C:\unattend.xml'
@'
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="generalize">
    <component name="Microsoft-Windows-PnpSysprep"
               processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35"
               versionScope="nonSxS"
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <PersistAllDeviceInstalls>true</PersistAllDeviceInstalls>
    </component>
  </settings>
</unattend>
'@ | Out-File 'C:\unattend.xml' -Encoding UTF8 -Force
}

# ───────────────────────── MAIN ────────────────────────────
try {
    Set-PowerPlanBalanced
    Enable-RDP
    Tune-TCP
    Set-AutomaticPagefile
    Clear-Temp
    Clear-WUCache
    Trim-WinSxS
    Clear-EventLogs
    Install-Virtio
    Install-CloudbaseInit
    Write-UnattendXml

    Write-Step '✅ Preparation complete.'
    Write-Step 'Run Sysprep when ready:'
    Write-Host  '   "%SystemRoot%\System32\Sysprep\Sysprep.exe" /generalize /oobe /shutdown /unattend:C:\unattend.xml' -ForegroundColor Yellow
}
catch {
    Write-Error "ERROR: $($_.Exception.Message)"
    Exit 1
}
finally {
    Stop-Transcript
    Write-Host "`nTranscript saved to $LogPath"
}
