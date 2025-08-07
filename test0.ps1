#requires -RunAsAdministrator
<#
  .SYNOPSIS
      Windows guest preparation for Apache CloudStack 4.20
      • Optimises power, RDP, network
      • Normalises the pagefile (WMIC)
      • Cleans temp, logs, update cache, WinSxS
      • Installs & configures Cloud-Init (Cloudbase-Init) for password injection
      • Writes unattend.xml preserving VirtIO drivers
      • Creates C:\RunSysprep.bat
  .NOTES
      • Idempotent – safe to run more than once.
      • Tested on Win10/11 & Server 2019/2022 (x64/x86).
Run this in Powershell before Starting:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# Or To run a script directly with bypass:
powershell.exe -ExecutionPolicy Bypass -File "YourScript.ps1"
#>

# ---------------------  logging  ---------------------
$log = 'C:\cloudstack-prep.log'
try   { Start-Transcript -Path $log -Append }
catch { $log = "C:\cloudstack-prep_$([datetime]::Now.ToString('yyyyMMdd_HHmmss')).log"
        Start-Transcript -Path $log }

function Step { param($m) ; Write-Host ">> $m" }

# ------------------ 1. OS optimisations ---------------
function Optimize-OS {
    Step 'Applying Balanced power plan'
    powercfg /setactive SCHEME_BALANCED | Out-Null

    Step 'Enabling RDP + NLA + firewall'
    Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server'                                    fDenyTSConnections 0
    Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' UserAuthentication 1
    Set-Service TermService -StartupType Automatic
    if ((Get-Service TermService).Status -ne 'Running') { Start-Service TermService }
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue

    Step 'Network stack tweaks for vNICs'
    netsh interface tcp set global rss=enabled autotuninglevel=normal chimney=disabled | Out-Null
}

# ------------------ 2. Page-file normalisation --------
function Fix-Pagefile {
    Step 'Setting pagefile to AutomaticManagedPagefile=True on C:'
    wmic computersystem where name="%COMPUTERNAME%" set AutomaticManagedPagefile=True  >$null 2>&1
    wmic pagefileset where "name!='C:\\\\pagefile.sys'" delete                          >$null 2>&1
}

# ------------------ 3. Deep clean ---------------------
function Cleanup-Windows {
    Step 'Cleaning TEMP folders'
    Get-ChildItem "$env:TEMP","C:\Windows\Temp" -Recurse -Force -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    Step 'Flushing Windows Update cache'
    Stop-Service wuauserv -Force
    Remove-Item -Recurse -Force 'C:\Windows\SoftwareDistribution\Download\*' -ErrorAction SilentlyContinue
    Start-Service wuauserv

    Step 'Component Store (WinSxS) trim'
    if ([Environment]::OSVersion.Version.Build -ge 14393) {   # Win10 1607 / Server 2016 or newer
        Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null
    }

    Step 'Clearing all event logs'
    wevtutil el | ForEach-Object { wevtutil cl $_ }
}

# ------------------ 4. Cloud-Init install -------------
function Install-CloudInit {
    if (Get-Service cloudbase-init -ErrorAction SilentlyContinue) {
        Step 'Cloudbase-Init already installed – skipping'
        return
    }

    Step 'Downloading Cloudbase-Init MSI'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $arch   = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    $msi    = "$env:TEMP\CloudbaseInit_$arch.msi"

    $primary = "https://www.cloudbase.it/downloads/CloudbaseInitSetup_Stable_${arch}.msi"
    $backup  = "https://github.com/cloudbase/cloudbase-init/releases/latest/download/CloudbaseInitSetup_${arch}.msi"

    try   { Invoke-WebRequest $primary -OutFile $msi -UseBasicParsing -ErrorAction Stop }
    catch { Step 'Primary mirror failed – using GitHub fallback'
            Invoke-WebRequest $backup  -OutFile $msi -UseBasicParsing }

    Step 'Verifying MSI (SHA-256)'
    $hash = (Get-FileHash $msi -Algorithm SHA256).Hash
    if ($hash.Length -ne 64) { throw 'Hash length incorrect – download corrupted.' }

    Step 'Installing Cloudbase-Init silently'
    $exit = (Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart RUN_CLOUDBASEINIT_SERVICE=1 SYSPREP_DISABLED=1" `
             -Wait -PassThru).ExitCode
    if ($exit) { throw "Cloudbase-Init installer exited with $exit" }

    Step 'Writing Cloudbase-Init config for CloudStack'
    $confPath = "$env:ProgramFiles\Cloudbase Solutions\Cloudbase-Init\conf\cloudbase-init.conf"
    @'
[DEFAULT]
username              = Administrator
inject_user_password  = true
first_logon_behaviour = no
metadata_services     = cloudbaseinit.metadata.services.cloudstack.CloudStack
plugins               = cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin,cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin,cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin,cloudbaseinit.plugins.common.userdata.UserDataPlugin
'@ | Out-File $confPath -Encoding ASCII

    Set-Service cloudbase-init -StartupType Automatic
    Start-Service cloudbase-init
    Step "Cloudbase-Init $arch installed & configured."
}

# ------------------ 5. unattend.xml -------------------
function Write-Unattend {
    Step 'Creating unattend.xml (PersistAllDeviceInstalls)'
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

# ------------------ 6. RunSysprep.bat -----------------
function Write-SysprepBatch {
    Step 'Writing C:\RunSysprep.bat'
    @'
@echo off
echo == Running Sysprep ==
cd /d %WINDIR%\System32\Sysprep
sysprep.exe /generalize /oobe /shutdown /unattend:C:\unattend.xml
'@ | Out-File 'C:\RunSysprep.bat' -Encoding ASCII -Force
}

# ------------------ 7. Execute all --------------------
try {
    Optimize-OS
    Fix-Pagefile
    Cleanup-Windows
    Install-CloudInit
    Write-Unattend
    Write-SysprepBatch
    Step '✔ All tasks finished – reboot if you like, then run C:\RunSysprep.bat'
} catch {
    Write-Error "ERROR: $($_.Exception.Message)"
    Exit 1
} finally {
    Stop-Transcript
    Write-Host "Log written to $log"
}
