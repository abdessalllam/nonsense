#requires -RunAsAdministrator
# prepare-cloudstack.ps1  –  Works on Windows Server 2016 → 2025

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ───────────────────────────── Transcript ─────────────────────────────
$Log = 'C:\cloudstack-prep.log'
try { Start-Transcript -Path $Log -Append }
catch {
    $Log = ('C:\cloudstack-prep_{0:yyyyMMdd_HHmmss}.log' -f (Get-Date))
    Start-Transcript -Path $Log -Append
}
function Step { param([string]$Msg); Write-Host "`n>> $Msg" }

# ───────────────────────── 1. OS tuning ───────────────────────────────
function Enable-OptimisedRdp {
    Step 'Enable RDP, NLA and open firewall'
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    Set-ItemProperty $base fDenyTSConnections 0
    Set-ItemProperty "$base\WinStations\RDP-Tcp" UserAuthentication 1
    Set-Service TermService -StartupType Automatic
    if ((Get-Service TermService).Status -ne 'Running') { Start-Service TermService }
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
}

function Apply-PowerAndTcp {
    Step 'Balanced power plan'
    powercfg /setactive SCHEME_BALANCED | Out-Null
    Step 'TCP flags (best-effort)'
    foreach ($flag in 'rss=enabled','autotuninglevel=normal','chimney=disabled') {
        cmd /c "netsh interface tcp set global $flag >nul 2>nul"
    }
}

# ───────────────────────── 2. Pagefile ────────────────────────────────
function Set-PagefileAutomatic {
    Step 'Pagefile → Automatic on C:'
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

# ───────────────────────── 3. Clean-up ────────────────────────────────
function Clean-System {
    Step 'Clear TEMP'
    Get-ChildItem "$env:TEMP","C:\Windows\Temp" -Recurse -Force -EA SilentlyContinue |
        Remove-Item -Recurse -Force -EA SilentlyContinue

    Step 'Flush Windows-Update cache'
    Stop-Service wuauserv -Force -EA SilentlyContinue
    Remove-Item 'C:\Windows\SoftwareDistribution\Download\*' -Recurse -Force -EA SilentlyContinue
    Start-Service wuauserv -EA SilentlyContinue

    if ([Environment]::OSVersion.Version.Build -ge 14393) {
        Step 'Trim WinSxS store'
        Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null
    }

    Step 'Clear event logs (protected logs skipped)'
    foreach ($logName in & wevtutil el) { & wevtutil cl "$logName" 1>$null 2>$null }
}

# ─────────────────── 4. VirtIO Guest-Tools ▶ 0.1.271 ──────────────────
function Install-Virtio {
    if (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |
        Where-Object { $_.DisplayName -like 'VirtIO*Guest*Tools*' }) {
        Step 'VirtIO Guest-Tools already installed – skipping'
        return
    }
    Step 'Download VirtIO Guest-Tools 0.1.271'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $arch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    $msi  = "$env:TEMP\virtio-$arch.msi"
    $url1 = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.271-1/virtio-win-gt-$arch.msi"
    $url2 = "https://fedora-virt.repo.nfrance.com/virtio-win/direct-downloads/stable-virtio/virtio-win-gt-$arch.msi"
    try   { Invoke-WebRequest $url1 -OutFile $msi -UseBasicParsing -EA Stop }
    catch { Step 'Primary mirror failed – using mirror 2'; Invoke-WebRequest $url2 -OutFile $msi -UseBasicParsing }
    Step 'Install VirtIO Guest-Tools (silent)'
    $rc = (Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -Wait -Passthru).ExitCode
    if ($rc) { throw "VirtIO installer exit-code $rc" }
}

# ──────────────── 5. Cloudbase-Init (cloud-init) ──────────────────────
function Install-CloudbaseInit {
    if (Get-Service cloudbase-init -EA SilentlyContinue) {
        Step 'Cloudbase-Init already present – skipping'; return
    }
    Step 'Download Cloudbase-Init'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $arch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    $msi  = "$env:TEMP\cloudbase-$arch.msi"
    $p1   = "https://www.cloudbase.it/downloads/CloudbaseInitSetup_Stable_${arch}.msi"
    $p2   = "https://github.com/cloudbase/cloudbase-init/releases/latest/download/CloudbaseInitSetup_${arch}.msi"
    try   { Invoke-WebRequest $p1 -OutFile $msi -UseBasicParsing -EA Stop }
    catch { Step 'Primary mirror failed – using GitHub'; Invoke-WebRequest $p2 -OutFile $msi -UseBasicParsing }
    Step 'Install Cloudbase-Init'
    $rc = (Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart RUN_CLOUDBASEINIT_SERVICE=1 SYSPREP_DISABLED=1" `
           -Wait -Passthru).ExitCode
    if ($rc) { throw "Cloudbase-Init installer exit-code $rc" }
    Step 'Configure Cloudbase-Init for CloudStack'
    $conf = "$env:ProgramFiles\Cloudbase Solutions\Cloudbase-Init\conf\cloudbase-init.conf"
@'
[DEFAULT]
username = Administrator
inject_user_password = true
first_logon_behaviour = no
metadata_services = cloudbaseinit.metadata.services.cloudstack.CloudStack
plugins = cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin,cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin,cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin,cloudbaseinit.plugins.common.userdata.UserDataPlugin
'@ | Out-File $conf -Encoding ASCII -Force
    Set-Service cloudbase-init -StartupType Automatic
    Start-Service cloudbase-init
}

# ───────────────── 6. unattend.xml (ASCII only) ───────────────────────
function Write-Unattend {
    Step 'Write C:\unattend.xml'
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
'@ | Out-File 'C:\unattend.xml' -Encoding ASCII -Force
}

# ───────────────────────────── Main ───────────────────────────────────
try {
    Enable-OptimisedRdp
    Apply-PowerAndTcp
    Set-PagefileAutomatic
    Clean-System
    Install-Virtio
    Install-CloudbaseInit
    Write-Unattend
    Step '✅ Preparation complete.'
    Step 'Sysprep when ready:'
    Write-Host '"%SystemRoot%\System32\Sysprep\Sysprep.exe" /generalize /oobe /shutdown /unattend:C:\unattend.xml' -ForegroundColor Yellow
}
catch {
    Write-Error "ERROR: $($_.Exception.Message)"
    Exit 1
}
finally {
    Stop-Transcript
    Write-Host "`nLog saved to $Log"
}
