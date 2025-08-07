#requires -RunAsAdministrator
<#
.SYNOPSIS
    Prepare a Windows guest for Apache CloudStack 4.20
      • Optimise power, RDP, network
      • Pagefile → Automatic (WMIC)
      • Deep-clean temp, logs, WinSxS, update cache
      • Install VirtIO guest-tools 0.1.271
      • Install & configure Cloud-Init (Cloudbase-Init) for password injection
      • Write C:\unattend.xml (PersistAllDeviceInstalls)
.NOTES
      • Safe to re-run (idempotent)
      • Tested on Win 10/11 & Server 2019/2022 (x64 + x86)
      • Full transcript → C:\cloudstack-prep.log
Run this in Powershell before Starting:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# Or To run a script directly with bypass:
powershell.exe -ExecutionPolicy Bypass -File "YourScript.ps1"
#>

# ---------- logging ----------
$log = 'C:\cloudstack-prep.log'
try   { Start-Transcript -Path $log -Append }
catch { $log = "C:\cloudstack-prep_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
        Start-Transcript -Path $log -Append }
function Step { param([string]$m) ; Write-Host ">> $m" }

# ---------- 1. optimise OS ----------
function Optimize-OS {
    Step 'Balanced power plan'
    powercfg /setactive SCHEME_BALANCED | Out-Null

    Step 'Enable RDP + NLA + firewall'
    Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' fDenyTSConnections 0
    Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' UserAuthentication 1
    Set-Service TermService -StartupType Automatic
    if ((Get-Service TermService).Status -ne 'Running') { Start-Service TermService }
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue

    Step 'TCP global tweaks (best-effort – unsupported flags are ignored)'
    foreach ($flag in @('rss=enabled','autotuninglevel=normal','chimney=disabled')) {
        cmd /c "netsh interface tcp set global $flag >nul 2>nul"
    }
}

# ---------- 2. pagefile ----------
function Fix-Pagefile {
    Step 'Pagefile → Automatic on C:'
    wmic computersystem where name="%COMPUTERNAME%" set AutomaticManagedPagefile=True  >$null 2>&1
    wmic pagefileset where "name!='C:\\\\pagefile.sys'" delete                          >$null 2>&1
}

# ---------- 3. clean Windows ----------
function Cleanup-Windows {
    Step 'Clear TEMP folders'
    Get-ChildItem "$env:TEMP","C:\Windows\Temp" -Recurse -Force -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    Step 'Flush Windows Update cache'
    Stop-Service wuauserv -Force
    Remove-Item -Recurse -Force 'C:\Windows\SoftwareDistribution\Download\*' -ErrorAction SilentlyContinue
    Start-Service wuauserv

    Step 'Trim WinSxS (modern builds only)'
    if ([Environment]::OSVersion.Version.Build -ge 14393) {
        Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null
    }

    Step 'Clear event logs (protected logs skipped silently)'
    foreach ($logName in & wevtutil el) { & wevtutil cl "$logName" 1>$null 2>$null }
}

# ---------- 4. VirtIO guest-tools ----------
function Install-VirtioDrivers {
    if (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'VirtIO.*Guest.*Tools' }) {
        Step 'VirtIO Guest-Tools already installed – skipping';  return
    }

    Step 'Download VirtIO Guest-Tools 0.1.271'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $arch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    $msi  = "$env:TEMP\virtio-gt-$arch.msi"
    $url1 = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.271-1/virtio-win-gt-$arch.msi"
    $url2 = "https://fedora-virt.repo.nfrance.com/virtio-win/direct-downloads/stable-virtio/virtio-win-gt-$arch.msi"   # mirror

    try   { Invoke-WebRequest $url1 -OutFile $msi -UseBasicParsing -ErrorAction Stop }
    catch { Step 'Primary mirror failed – using mirror 2'
            Invoke-WebRequest $url2 -OutFile $msi -UseBasicParsing }

    Step 'Install VirtIO Guest-Tools silently'
    $rc = (Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -Wait -PassThru).ExitCode
    if ($rc) { throw "VirtIO installer exited with code $rc" }
    Step 'VirtIO Guest-Tools installed.'
}

# ---------- 5. Cloud-Init ----------
function Install-CloudInit {
    if (Get-Service cloudbase-init -ErrorAction SilentlyContinue) {
        Step 'Cloudbase-Init already installed – skipping';  return
    }

    Step 'Download Cloudbase-Init MSI'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $arch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    $msi  = "$env:TEMP\CloudbaseInit_$arch.msi"
    $pri  = "https://www.cloudbase.it/downloads/CloudbaseInitSetup_Stable_${arch}.msi"
    $bak  = "https://github.com/cloudbase/cloudbase-init/releases/latest/download/CloudbaseInitSetup_${arch}.msi"

    try   { Invoke-WebRequest $pri -OutFile $msi -UseBasicParsing -ErrorAction Stop }
    catch { Step 'Primary mirror failed – using GitHub'
            Invoke-WebRequest $bak -OutFile $msi -UseBasicParsing }

    Step 'Install Cloudbase-Init silently'
    $rc = (Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart RUN_CLOUDBASEINIT_SERVICE=1 SYSPREP_DISABLED=1" `
          -Wait -PassThru).ExitCode
    if ($rc) { throw "Cloudbase-Init installer exited with code $rc" }

    Step 'Configure Cloudbase-Init for CloudStack'
    $conf = "$env:ProgramFiles\Cloudbase Solutions\Cloudbase-Init\conf\cloudbase-init.conf"
@'
[DEFAULT]
username              = Administrator
inject_user_password  = true
first_logon_behaviour = no
metadata_services     = cloudbaseinit.metadata.services.cloudstack.CloudStack
plugins               = cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin,cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin,cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin,cloudbaseinit.plugins.common.userdata.UserDataPlugin
'@ | Out-File $conf -Encoding ASCII -Force

    Set-Service cloudbase-init -StartupType Automatic
    Start-Service cloudbase-init
    Step 'Cloudbase-Init ready.'
}

# ---------- 6. unattend.xml ----------
function Write-Unattend {
    Step 'Writing C:\unattend.xml'
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

# ---------- 7. execute ----------
try {
    Optimize-OS
    Fix-Pagefile
    Cleanup-Windows
    Install-VirtioDrivers
    Install-CloudInit
    Write-Unattend
    Step '✔ Preparation complete — reboot, then sysprep with C:\unattend.xml when ready.'
} catch {
    Write-Error "ERROR: $($_.Exception.Message)";  Exit 1
} finally {
    Stop-Transcript
    Write-Host "Log saved to $log"
}
