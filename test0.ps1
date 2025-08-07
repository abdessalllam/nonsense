#requires -RunAsAdministrator
#==============================================================================
#  prepare-cloudstack.ps1
#  ---------------------------------------------------------------------------
#  Prepares a Windows Server guest (2016 → 2025) for Apache CloudStack 4.20+
#    • Enables RDP (with NLA) and opens the firewall rule
#    • Uses the Balanced power plan
#    • Applies basic TCP off-load tweaks (best-effort per flag)
#    • Sets the system pagefile to “Automatic” on C:
#    • Cleans TEMP folders, Windows Update cache, WinSxS (modern builds) and
#      clears event logs without failing on protected channels
#    • Downloads & installs VirtIO-Win Guest-Tools 0.1.271 (x86/x64)
#    • Downloads & installs Cloudbase-Init (cloud-init for Windows) and
#      configures it for CloudStack’s metadata service
#    • Writes C:\unattend.xml so VirtIO drivers persist after Sysprep
#    • Writes a full transcript to C:\cloudstack-prep.log
#    • All steps are safe to re-run
#==============================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#------------------------------------------------------------------------------
# 0. Logging
#------------------------------------------------------------------------------
$LogPath = 'C:\cloudstack-prep.log'
try { Start-Transcript -Path $LogPath -Append }
catch {
    $LogPath = "C:\cloudstack-prep_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
    Start-Transcript -Path $LogPath -Append
}

function Write-Step {
    param([string]$Message)
    Write-Host ("`n>> {0}" -f $Message)
}

#------------------------------------------------------------------------------
# 1. Optimise OS (power-plan, RDP, TCP)
#------------------------------------------------------------------------------
function Set-PowerPlanBalanced {
    Write-Step 'Setting Balanced power plan'
    powercfg /setactive SCHEME_BALANCED | Out-Null
}

function Enable-RDP {
    Write-Step 'Enabling RDP (with NLA) and firewall rule'
    $tsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    Set-ItemProperty -Path $tsKey -Name fDenyTSConnections -Value 0
    Set-ItemProperty -Path "$tsKey\WinStations\RDP-Tcp" -Name UserAuthentication -Value 1
    Set-Service  -Name TermService -StartupType Automatic
    if ((Get-Service TermService).Status -ne 'Running') { Start-Service TermService }
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
}

function Tweak-TCPStack {
    Write-Step 'Applying TCP global flags (best-effort)'
    $flags = 'rss=enabled', 'autotuninglevel=normal', 'chimney=disabled'
    foreach ($flag in $flags) {
        cmd /c "netsh interface tcp set global $flag >nul 2>nul"
    }
}

#------------------------------------------------------------------------------
# 2. Pagefile → automatic on C:
#------------------------------------------------------------------------------
function Set-AutomaticPagefile {
    Write-Step 'Setting AutomaticManagedPagefile=True on C:'
    if (Get-Command wmic -ErrorAction SilentlyContinue) {
        wmic computersystem where name="%COMPUTERNAME%" set AutomaticManagedPagefile=True  >$null 2>&1
        wmic pagefileset where "name!='C:\\\\pagefile.sys'" delete                          >$null 2>&1
    } else {
        # WMIC removed (newer builds). Use CIM instead.
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        if (-not $cs.AutomaticManagedPagefile) {
            Set-CimInstance -InputObject $cs -Property @{ AutomaticManagedPagefile = $true }
        }
    }
}

#------------------------------------------------------------------------------
# 3. House-keeping
#------------------------------------------------------------------------------
function Clear-Temp {
    Write-Step 'Clearing TEMP folders'
    $paths = @("$env:TEMP", 'C:\Windows\Temp')
    foreach ($p in $paths) {
        Get-ChildItem $p -Recurse -Force -ErrorAction SilentlyContinue |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Clear-WindowsUpdateCache {
    Write-Step 'Flushing Windows Update cache'
    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force 'C:\Windows\SoftwareDistribution\Download\*' -ErrorAction SilentlyContinue
    Start-Service wuauserv -ErrorAction SilentlyContinue
}

function Trim-WinSxS {
    if ([Environment]::OSVersion.Version.Build -ge 14393) {   # Server 2016 / 1607+
        Write-Step 'Running WinSxS component cleanup'
        Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null
    }
}

function Clear-EventLogs {
    Write-Step 'Clearing event logs (protected logs skipped)'
    foreach ($logName in & wevtutil el) {
        & wevtutil cl "$logName" 1>$null 2>$null
    }
}

#------------------------------------------------------------------------------
# 4. Install VirtIO Guest-Tools 0.1.271
#------------------------------------------------------------------------------
function Install-Virtio {
    if (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue |
        Where-Object { $_.DisplayName -match 'VirtIO.*Guest.*Tools' }) {
        Write-Step 'VirtIO Guest-Tools already present – skipping'
        return
    }

    Write-Step 'Downloading VirtIO Guest-Tools 0.1.271'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $Arch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    $Msi  = "$env:TEMP\virtio-gt-$Arch.msi"

    $UrlPrimary = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.271-1/virtio-win-gt-$Arch.msi"
    $UrlMirror  = "https://fedora-virt.repo.nfrance.com/virtio-win/direct-downloads/stable-virtio/virtio-win-gt-$Arch.msi"

    try   { Invoke-WebRequest $UrlPrimary -OutFile $Msi -UseBasicParsing -EA Stop }
    catch { Write-Step 'Primary mirror failed; trying secondary'
            Invoke-WebRequest $UrlMirror  -OutFile $Msi -UseBasicParsing }

    Write-Step 'Installing VirtIO Guest-Tools (silent)'
    $code = (Start-Process msiexec.exe -ArgumentList "/i `"$Msi`" /qn /norestart" -Wait -PassThru).ExitCode
    if ($code) { throw "VirtIO installer exit code $code" }
    Write-Step 'VirtIO Guest-Tools installed'
}

#------------------------------------------------------------------------------
# 5. Install & configure Cloudbase-Init
#------------------------------------------------------------------------------
function Install-CloudbaseInit {
    if (Get-Service cloudbase-init -EA SilentlyContinue) {
        Write-Step 'Cloudbase-Init already installed – skipping'
        return
    }

    Write-Step 'Downloading Cloudbase-Init (stable build)'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $Arch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    $Msi  = "$env:TEMP\cloudbase-init-$Arch.msi"

    $UrlPrimary = "https://www.cloudbase.it/downloads/CloudbaseInitSetup_Stable_${Arch}.msi"
    $UrlMirror  = "https://github.com/cloudbase/cloudbase-init/releases/latest/download/CloudbaseInitSetup_${Arch}.msi"

    try   { Invoke-WebRequest $UrlPrimary -OutFile $Msi -UseBasicParsing -EA Stop }
    catch { Write-Step 'Primary mirror failed; using GitHub'
            Invoke-WebRequest $UrlMirror  -OutFile $Msi -UseBasicParsing }

    Write-Step 'Installing Cloudbase-Init (silent)'
    $code = (Start-Process msiexec.exe -ArgumentList "/i `"$Msi`" /qn /norestart RUN_CLOUDBASEINIT_SERVICE=1 SYSPREP_DISABLED=1" `
             -Wait -PassThru).ExitCode
    if ($code) { throw "Cloudbase-Init installer exit code $code" }

    Write-Step 'Writing Cloudbase-Init config for CloudStack'
    $CfgPath = "$env:ProgramFiles\Cloudbase Solutions\Cloudbase-Init\conf\cloudbase-init.conf"
@'
[DEFAULT]
username              = Administrator
inject_user_password  = true
first_logon_behaviour = no
metadata_services     = cloudbaseinit.metadata.services.cloudstack.CloudStack
plugins               = cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin,cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin,cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin,cloudbaseinit.plugins.common.userdata.UserDataPlugin
'@ | Out-File $CfgPath -Encoding ASCII -Force

    Set-Service cloudbase-init -StartupType Automatic
    Start-Service cloudbase-init
    Write-Step 'Cloudbase-Init installed and started'
}

#------------------------------------------------------------------------------
# 6. Write unattend.xml that preserves VirtIO drivers
#------------------------------------------------------------------------------
function Write-UnattendXml {
    Write-Step 'Creating C:\unattend.xml'
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

#------------------------------------------------------------------------------
# 7. Main routine
#------------------------------------------------------------------------------
try {
    Set-PowerPlanBalanced
    Enable-RDP
    Tweak-TCPStack
    Set-AutomaticPagefile
    Clear-Temp
    Clear-WindowsUpdateCache
    Trim-WinSxS
    Clear-EventLogs
    Install-Virtio
    Install-CloudbaseInit
    Write-UnattendXml
    Write-Step '*** ALL DONE *** – reboot once, then sysprep with:'
    Write-Step '    "%windir%\System32\Sysprep\Sysprep.exe" /generalize /oobe /shutdown /unattend:C:\unattend.xml'
}
catch {
    Write-Error "FATAL: $($_.Exception.Message)"
    Exit 1
}
finally {
    Stop-Transcript
    Write-Host "`nTranscript saved to $LogPath"
}
