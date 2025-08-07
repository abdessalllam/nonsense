#requires -RunAsAdministrator
<#
  .SYNOPSIS
      Windows guest preparation for Apache CloudStack 4.20
      • Optimises power, RDP & network
      • Normalises the pagefile (WMIC)
      • Cleans temp, logs, update cache, WinSxS
      • Installs VirtIO 0.1.271 guest-tools + drivers
      • Installs Cloud-Init (Cloudbase-Init) for password injection
      • Writes unattend.xml (PersistAllDeviceInstalls)
  .NOTES
      • Idempotent – safe to re-run.
      • Tested on Win10/11 & Server 2019/2022 (x64/x86) on KVM + VirtIO.
      • Full transcript → C:\cloudstack-prep.log
Run this in Powershell before Starting:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# Or To run a script directly with bypass:
powershell.exe -ExecutionPolicy Bypass -File "YourScript.ps1"
#>

# -------------------- Logging ------------------------
$log = 'C:\cloudstack-prep.log'
try   { Start-Transcript -Path $log -Append }
catch { $fallback = "C:\cloudstack-prep_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
        Start-Transcript -Path $fallback -Append
        $log = $fallback }

function Step { param([string]$m) ; Write-Host ">> $m" }

# ------------------ 1. Optimise OS -------------------
function Optimize-OS {
    Step 'Power plan → Balanced'
    powercfg /setactive SCHEME_BALANCED | Out-Null

    Step 'Enabling RDP + NLA + firewall'
    Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' fDenyTSConnections 0
    Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' UserAuthentication 1
    Set-Service TermService -StartupType Automatic
    if ((Get-Service TermService).Status -ne 'Running') { Start-Service TermService }
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue

    Step 'TCP tuning (RSS on, autotune normal, chimney off)'
    netsh interface tcp set global rss=enabled autotuninglevel=normal chimney=disabled | Out-Null   #
}

# ------------------ 2. Page-file ---------------------
function Fix-Pagefile {
    Step 'Pagefile → Automatic on C:'
    wmic computersystem where name="%COMPUTERNAME%" set AutomaticManagedPagefile=True  >$null 2>&1
    wmic pagefileset   where "name!='C:\\\\pagefile.sys'" delete                        >$null 2>&1   #
}

# ------------------ 3. Clean-up ----------------------
function Cleanup-Windows {
    Step 'Purging TEMP folders'
    Get-ChildItem "$env:TEMP","C:\Windows\Temp" -Recurse -Force -EA SilentlyContinue |
        Remove-Item -Recurse -Force -EA SilentlyContinue

    Step 'Flushing Windows Update cache'
    Stop-Service wuauserv -Force
    Remove-Item -Recurse -Force 'C:\Windows\SoftwareDistribution\Download\*' -EA SilentlyContinue
    Start-Service wuauserv

    Step 'Component store trim (WinSxS)'
    if ([Environment]::OSVersion.Version.Build -ge 14393) {   # Win10 1607 / Server 2016+
        Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null
    }

    Step 'Clearing event logs (skip protected logs)'
    wevtutil el | ForEach-Object {
        try   { wevtutil cl $_ 2>$null }
        catch { Write-Verbose "Skipped $_ – $($_.Exception.Message)" }
    }
}

# ------------------ 4. VirtIO guest-tools ------------
function Install-VirtioDrivers {
    if (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue |
        Where-Object { $_.DisplayName -match 'VirtIO.*Guest.*Tools' }) {
        Step 'VirtIO Guest-Tools already installed – skipping'
        return
    }

    Step 'Downloading VirtIO Guest-Tools 0.1.271'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $arch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    $msi  = "$env:TEMP\virtio-gt-$arch.msi"

    $url1 = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.271-1/virtio-win-gt-$arch.msi"
    $url2 = "https://fedora-virt.repo.nfrance.com/virtio-win/direct-downloads/stable-virtio/virtio-win-gt-$arch.msi"   #

    try   { Invoke-WebRequest $url1 -OutFile $msi -UseBasicParsing -EA Stop }
    catch { Step 'Primary mirror failed – using mirror 2'
            Invoke-WebRequest $url2 -OutFile $msi -UseBasicParsing }

    Step 'Installing VirtIO Guest-Tools silently'
    $rc = (Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -Wait -PassThru).ExitCode
    if ($rc) { throw "VirtIO installer exited with code $rc" }
    Step 'VirtIO Guest-Tools installed.'
}

# ------------------ 5. Cloud-Init --------------------
function Install-CloudInit {
    if (Get-Service cloudbase-init -EA SilentlyContinue) {
        Step 'Cloudbase-Init already installed – skipping'
        return
    }

    Step 'Downloading Cloudbase-Init MSI'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $arch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    $msi  = "$env:TEMP\CloudbaseInit_$arch.msi"

    $pri  = "https://www.cloudbase.it/downloads/CloudbaseInitSetup_Stable_${arch}.msi"
    $bak  = "https://github.com/cloudbase/cloudbase-init/releases/latest/download/CloudbaseInitSetup_${arch}.msi"

    try   { Invoke-WebRequest $pri -OutFile $msi -UseBasicParsing -EA Stop }
    catch { Step 'Primary mirror failed – using GitHub'
            Invoke-WebRequest $bak -OutFile $msi -UseBasicParsing }

    Step 'Installing Cloudbase-Init silently'
    $rc = (Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart RUN_CLOUDBASEINIT_SERVICE=1 SYSPREP_DISABLED=1" `
          -Wait -PassThru).ExitCode
    if ($rc) { throw "Cloudbase-Init installer exited with code $rc" }

    Step 'Configuring Cloudbase-Init for CloudStack'
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
    Step 'Cloudbase-Init ready.'   #
}

# ------------------ 6. unattend.xml ------------------
function Write-Unattend {
    Step 'Writing unattend.xml (keeps VirtIO after Sysprep)'
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
'@ | Out-File 'C:\unattend.xml' -Encoding UTF8 -Force   #
}

# ------------------ 7. Run everything ----------------
try {
    Optimize-OS
    Fix-Pagefile
    Cleanup-Windows
    Install-VirtioDrivers
    Install-CloudInit
    Write-Unattend
    Step '✔ Preparation complete – reboot, then sysprep whenever you’re ready.'
} catch {
    Write-Error "ERROR: $($_.Exception.Message)"
    Exit 1
} finally {
    Stop-Transcript
    Write-Host "Log saved to $log"
}
