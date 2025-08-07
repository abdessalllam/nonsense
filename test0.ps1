#requires -RunAsAdministrator
<#
  PREPARES a Windows guest for Apache CloudStack 4.20
    • Optimise power, RDP, basic TCP
    • Pagefile → automatic (WMIC, widest compatibility)
    • Deep-clean TEMP, event-logs, WinSxS, WU cache
    • Install VirtIO Guest-Tools 0.1.271 (x86 / x64)
    • Install & configure Cloudbase-Init for CloudStack password injection
    • Write C:\unattend.xml (keeps VirtIO drivers after Sysprep)
    • Fully idempotent – safe to re-run
#>

# ───────────────────────── LOGGING ─────────────────────────
$log = 'C:\cloudstack-prep.log'
try { 
    Start-Transcript -Path $log -Append 
}
catch { 
    $log = "C:\cloudstack-prep_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss')
    Start-Transcript -Path $log -Append 
}

function Step { 
    param([string]$m) 
    Write-Host ">> $m" -ForegroundColor Cyan 
}

# ─────────────────── 1. OS OPTIMISATION ───────────────────
function Optimize-OS {
    Step 'Balanced power plan'
    powercfg /setactive SCHEME_BALANCED | Out-Null

    Step 'Enable RDP + NLA + firewall'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1
    Set-Service TermService -StartupType Automatic
    if ((Get-Service TermService).Status -ne 'Running') { 
        Start-Service TermService 
    }
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue

    Step 'TCP global flags (best-effort – unsupported ones ignored)'
    # Setting TCP optimization flags - some may not be available on all Windows versions
    foreach ($flag in @('rss=enabled','autotuninglevel=normal','chimney=disabled')) {
        cmd /c "netsh interface tcp set global $flag >nul 2>nul"
    }
}

# ─────────────────── 2. PAGEFILE FIX ──────────────────────
function Fix-Pagefile {
    Step 'Pagefile → Automatic on C:'
    & wmic computersystem where "name='$env:COMPUTERNAME'" set AutomaticManagedPagefile=True 2>&1 | Out-Null
    & wmic pagefileset where "name!='C:\\pagefile.sys'" delete 2>&1 | Out-Null
}

# ─────────────────── 3. WINDOWS CLEAN-UP ──────────────────
function Cleanup-Windows {
    Step 'Flush TEMP folders'
    @("$env:TEMP", "C:\Windows\Temp") | ForEach-Object {
        if (Test-Path $_) {
            Get-ChildItem $_ -Recurse -Force -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Step 'Flush Windows Update download cache'
    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    if (Test-Path 'C:\Windows\SoftwareDistribution\Download') {
        Remove-Item -Recurse -Force 'C:\Windows\SoftwareDistribution\Download\*' -ErrorAction SilentlyContinue
    }
    Start-Service wuauserv -ErrorAction SilentlyContinue

    Step 'Trim WinSxS (modern builds only)'
    if ([Environment]::OSVersion.Version.Build -ge 14393) {   # 1607 / Server 2016+
        Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null
    }

    Step 'Clear event logs – protected logs silently skipped'
    foreach ($logName in & wevtutil el) { 
        & wevtutil cl "$logName" 1>$null 2>$null 
    }
}

# ─────────────────── 4. VIRTIO 0.1.271 ────────────────────
function Install-VirtioDrivers {
    if (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'VirtIO.*Guest.*Tools' }) {
        Step 'VirtIO Guest-Tools already installed – skipping'
        return
    }

    Step 'Download VirtIO Guest-Tools 0.1.271'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $arch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    $msi  = "$env:TEMP\virtio-gt-$arch.msi"
    
    # Primary URL from Fedora People
    $url1 = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.271-1/virtio-win-gt-$arch.msi"
    # Alternate mirror for redundancy
    $url2 = "https://fedora-virt.repo.nfrance.com/virtio-win/direct-downloads/stable-virtio/virtio-win-gt-$arch.msi"

    try {
        Invoke-WebRequest $url1 -OutFile $msi -UseBasicParsing -ErrorAction Stop
    }
    catch {
        Step 'Primary mirror failed – trying alternate mirror'
        try {
            Invoke-WebRequest $url2 -OutFile $msi -UseBasicParsing -ErrorAction Stop
        }
        catch {
            throw "Failed to download VirtIO drivers from both mirrors"
        }
    }

    Step 'Install VirtIO Guest-Tools silently'
    $rc = (Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -Wait -PassThru).ExitCode
    if ($rc) { 
        throw "VirtIO installer exited with code $rc" 
    }
    Step 'VirtIO Guest-Tools installed successfully'
}

# ─────────────────── 5. CLOUDBASE-INIT ───────────────────
function Install-CloudInit {
    if (Get-Service cloudbase-init -ErrorAction SilentlyContinue) {
        Step 'Cloudbase-Init already installed – skipping'
        return
    }

    Step 'Download Cloudbase-Init MSI'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $arch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    $msi  = "$env:TEMP\CloudbaseInit_$arch.msi"
    $pri  = "https://www.cloudbase.it/downloads/CloudbaseInitSetup_Stable_${arch}.msi"
    $bak  = "https://github.com/cloudbase/cloudbase-init/releases/latest/download/CloudbaseInitSetup_${arch}.msi"

    try {
        Invoke-WebRequest $pri -OutFile $msi -UseBasicParsing -ErrorAction Stop
    }
    catch {
        Step 'Primary mirror failed – trying GitHub'
        try {
            Invoke-WebRequest $bak -OutFile $msi -UseBasicParsing -ErrorAction Stop
        }
        catch {
            throw "Failed to download Cloudbase-Init from both sources"
        }
    }

    Step 'Install Cloudbase-Init silently'
    $rc = (Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart RUN_CLOUDBASEINIT_SERVICE=1 SYSPREP_DISABLED=1" `
          -Wait -PassThru).ExitCode
    if ($rc) {
        throw "Cloudbase-Init installer exited with code $rc"
    }

    Step 'Configure Cloudbase-Init for CloudStack metadata'
    $conf = "$env:ProgramFiles\Cloudbase Solutions\Cloudbase-Init\conf\cloudbase-init.conf"
    
    # Create directory if it doesn't exist
    $confDir = Split-Path $conf -Parent
    if (!(Test-Path $confDir)) {
        New-Item -ItemType Directory -Path $confDir -Force | Out-Null
    }
    
@'
[DEFAULT]
username              = Administrator
inject_user_password  = true
first_logon_behaviour = no
metadata_services     = cloudbaseinit.metadata.services.cloudstack.CloudStack
plugins               = cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin,cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin,cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin,cloudbaseinit.plugins.common.userdata.UserDataPlugin
'@ | Out-File $conf -Encoding ASCII -Force

    Set-Service cloudbase-init -StartupType Automatic
    Start-Service cloudbase-init -ErrorAction SilentlyContinue
    Step 'Cloudbase-Init configured and ready'
}

# ─────────────────── 6. UNATTEND.XML ─────────────────────
function Write-Unattend {
    Step 'Write C:\unattend.xml (preserves VirtIO after Sysprep)'
    
    # Detect processor architecture for unattend.xml
    $procArch = if ([Environment]::Is64BitOperatingSystem) { 'amd64' } else { 'x86' }
    
    $unattendContent = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="generalize">
    <component name="Microsoft-Windows-PnpSysprep"
               processorArchitecture="$procArch"
               publicKeyToken="31bf3856ad364e35"
               versionScope="nonSxS"
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <PersistAllDeviceInstalls>true</PersistAllDeviceInstalls>
    </component>
  </settings>
</unattend>
"@
    
    $unattendContent | Out-File 'C:\unattend.xml' -Encoding UTF8 -Force
}

# ─────────────────── 7. RUN ALL ────────────────────────
try {
    Write-Host "`n=== CloudStack Windows Guest Preparation Starting ===" -ForegroundColor Green
    
    Optimize-OS
    Fix-Pagefile
    Cleanup-Windows
    Install-VirtioDrivers
    Install-CloudInit
    Write-Unattend
    
    Write-Host "`n=== CloudStack Windows Guest Preparation Complete ===" -ForegroundColor Green
    Step '✔ Prep complete — reboot once, then sysprep with:'
    Write-Host '   %windir%\System32\Sysprep\Sysprep.exe /generalize /oobe /shutdown /unattend:C:\unattend.xml' -ForegroundColor Yellow
    Write-Host ""
} 
catch {
    Write-Error "ERROR: $($_.Exception.Message)"
    Write-Host "`nStack Trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace
    exit 1
} 
finally {
    Stop-Transcript
    Write-Host "Log saved to: $log" -ForegroundColor Gray
}
