#requires -RunAsAdministrator
# prepare-cloudstack.ps1  (Windows Server 2016 – 2025, idempotent)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ───────── Transcript ─────────
$Log = 'C:\cloudstack-prep.log'
try { Start-Transcript -Path $Log -Append }
catch {
    $Log = ('C:\cloudstack-prep_{0:yyyyMMdd_HHmmss}.log' -f (Get-Date))
    Start-Transcript -Path $Log -Append
}
function Step { param([string]$Msg) ; Write-Host "`n>> $Msg" }

# ───────── 1.  OS tuning ─────────
function Enable-RdpNlaFirewall {
    Step 'Enable RDP + NLA + Firewall rule'
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    Set-ItemProperty $ts fDenyTSConnections 0
    Set-ItemProperty "$ts\WinStations\RDP-Tcp" UserAuthentication 1
    Set-Service TermService -StartupType Automatic
    if ((Get-Service TermService).Status -ne 'Running') { Start-Service TermService }
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
}
function Apply-PowerAndTcpFlags {
    Step 'Balanced power plan'
    powercfg /setactive SCHEME_BALANCED | Out-Null
    Step 'TCP flags (ignore if OS lacks flag)'
    foreach ($flag in 'rss=enabled','autotuninglevel=normal','chimney=disabled') {
        cmd /c "netsh interface tcp set global $flag >nul 2>nul"
    }
}

# ───────── 2.  Pagefile ─────────
function Set-PagefileAutomatic {
    Step 'Pagefile set to Automatic on C:'
    if (Get-Command wmic -ErrorAction SilentlyContinue) {
        wmic computersystem where name="%COMPUTERNAME%" set AutomaticManagedPagefile=True  >$null 2>&1
        wmic pagefileset where "name!='C:\\\\pagefile.sys'" delete                          >$null 2>&1
    } else {
        $cs = Get-CimInstance Win32_ComputerSystem
        if (-not $cs.AutomaticManagedPagefile) {
            Set-CimInstance $cs -Property @{AutomaticManagedPagefile=$true}
        }
    }
}

# ───────── 3.  Clean-up ─────────
function Clean-System {
    Step 'Clear TEMP folders'
    Get-ChildItem "$env:TEMP","C:\Windows\Temp" -Recurse -Force -EA SilentlyContinue |
        Remove-Item -Recurse -Force -EA SilentlyContinue
    Step 'Flush Windows Update cache'
    Stop-Service wuauserv -Force -EA SilentlyContinue
    Remove-Item 'C:\Windows\SoftwareDistribution\Download\*' -Recurse -Force -EA SilentlyContinue
    Start-Service wuauserv -EA SilentlyContinue
    if ([Environment]::OSVersion.Version.Build -ge 14393) {
        Step 'Trim WinSxS component store'
        Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null
    }
    Step 'Clear event logs (protected logs skipped)'
    foreach ($n in & wevtutil el) { & wevtutil cl "$n" 1>$null 2>$null }
}

# ───────── 4.  VirtIO Guest-Tools 0.1.271 ─────────
function Install-Virtio {
    $exists = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |
              Where-Object { $_.DisplayName -like 'VirtIO*Guest*Tools*' }
    if ($exists) { Step 'VirtIO already installed – skipping'; return }
    Step 'Download VirtIO Guest-Tools 0.1.271'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $arch  = ([Environment]::Is64BitOperatingSystem) ? 'x64' : 'x86'
    $msi   = "$env:TEMP\virtio-$arch.msi"
    $urlP  = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.271-1/virtio-win-gt-$arch.msi"  # cite :contentReference[oaicite:0]{index=0}
    $urlBk = "https://fedora-virt.repo.nfrance.com/virtio-win/direct-downloads/latest-virtio/virtio-win-gt-$arch.msi"                       # cite :contentReference[oaicite:1]{index=1}
    try   { Invoke-WebRequest $urlP -OutFile $msi -UseBasicParsing -EA Stop }
    catch { Step 'Primary mirror down – using mirror'; Invoke-WebRequest $urlBk -OutFile $msi -UseBasicParsing }
    Step 'Install VirtIO (silent)'
    $rc = (Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -Wait -Passthru).ExitCode
    if ($rc) { throw "VirtIO installer exit-code $rc" }
}

# ───────── 5.  Cloudbase-Init ─────────
function Install-CloudbaseInit {
    if (Get-Service cloudbase-init -EA SilentlyContinue) {
        Step 'Cloudbase-Init already installed – skipping'; return
    }
    Step 'Download Cloudbase-Init'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $arch = ([Environment]::Is64BitOperatingSystem) ? 'x64' : 'x86'
    $msi  = "$env:TEMP\cloudbase-$arch.msi"
    $up   = "https://www.cloudbase.it/downloads/CloudbaseInitSetup_Stable_${arch}.msi"                                        # cite :contentReference[oaicite:2]{index=2}
    $ub   = "https://github.com/cloudbase/cloudbase-init/releases/latest/download/CloudbaseInitSetup_${arch}.msi"
    try   { Invoke-WebRequest $up -OutFile $msi -UseBasicParsing -EA Stop }
    catch { Step 'Primary mirror down – using GitHub'; Invoke-WebRequest $ub -OutFile $msi -UseBasicParsing }
    Step 'Install Cloudbase-Init'
    $rc = (Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart RUN_CLOUDBASEINIT_SERVICE=1 SYSPREP_DISABLED=1" `
           -Wait -Passthru).ExitCode
    if ($rc) { throw "Cloudbase-Init installer exit-code $rc" }
    Step 'Write Cloudbase-Init config'
    $cfgPath = "$env:ProgramFiles\Cloudbase Solutions\Cloudbase-Init\conf\cloudbase-init.conf"
    $cfgContent = @'
[DEFAULT]
username = Administrator
inject_user_password = true
first_logon_behaviour = no
metadata_services = cloudbaseinit.metadata.services.cloudstack.CloudStack
plugins = cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin,cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin,cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin,cloudbaseinit.plugins.common.userdata.UserDataPlugin
'@
    $cfgContent | Out-File $cfgPath -Encoding ASCII -Force
    Set-Service cloudbase-init -StartupType Automatic
    Start-Service cloudbase-init
}

# ───────── 6.  unattend.xml (ASCII) ─────────
function Write-Unattend {
    Step 'Create C:\unattend.xml'
    $xml = @'
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
'@
    $xml | Out-File 'C:\unattend.xml' -Encoding ASCII -Force
}

# ───────── Main ─────────
try {
    Enable-RdpNlaFirewall
    Apply-PowerAndTcpFlags
    Set-PagefileAutomatic
    Clean-System
    Install-Virtio
    Install-CloudbaseInit
    Write-Unattend
    Step 'Preparation finished. Run Sysprep when ready:'
    Write-Host '"%SystemRoot%\System32\Sysprep\Sysprep.exe" /generalize /oobe /shutdown /unattend:C:\unattend.xml' -ForegroundColor Yellow
}
catch {
    Write-Error "ERROR: $($_.Exception.Message)"
    Exit 1
}
finally {
    Stop-Transcript
    Write-Host "`nTranscript saved to $Log"
}
