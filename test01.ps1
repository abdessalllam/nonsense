#requires -RunAsAdministrator
<#
  PREPARES a Windows guest for Apache CloudStack 4.20
    - Optimise power, RDP, basic TCP
    - Pagefile automatic (WMIC, widest compatibility)
    - Deep-clean TEMP, event-logs, WinSxS, WU cache
    - Install VirtIO Guest-Tools 0.1.271 (x86 / x64)
    - Install & configure Cloudbase-Init for CloudStack password injection
    - Write C:\unattend.xml (keeps VirtIO drivers after Sysprep)
    - Fully idempotent safe to re-run
#>

# LOGGING
$log = 'C:\cloudstack-prep.log'
try { 
    Start-Transcript -Path $log -Append 
}
catch { 
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $log = "C:\cloudstack-prep_$timestamp.log"
    Start-Transcript -Path $log -Append 
}

function Step { 
    param([string]$m) 
    Write-Host ">> $m" -ForegroundColor Cyan 
}

# 1. OS OPTIMISATION
function Optimize-OS {
    Step 'Balanced power plan'
    powercfg /setactive SCHEME_BALANCED | Out-Null

    Step 'Enable RDP + NLA + firewall'
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1
    Set-Service TermService -StartupType Automatic
    $rdpService = Get-Service TermService
    if ($rdpService.Status -ne 'Running') { 
        Start-Service TermService 
    }
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue

    Step 'TCP global flags (best-effort unsupported ones ignored)'
    $tcpFlags = 'rss=enabled', 'autotuninglevel=normal', 'chimney=disabled'
    foreach ($flag in $tcpFlags) {
        $cmd = "netsh interface tcp set global $flag"
        cmd /c "$cmd >nul 2>nul"
    }
}

# 2. PAGEFILE FIX
function Fix-Pagefile {
    Step 'Pagefile Automatic on C:'
    $wmicCmd1 = "wmic computersystem where name='%COMPUTERNAME%' set AutomaticManagedPagefile=True"
    cmd /c "$wmicCmd1 >nul 2>&1"
    $wmicCmd2 = "wmic pagefileset where `"name!='C:\\pagefile.sys'`" delete"
    cmd /c "$wmicCmd2 >nul 2>&1"
}

# 3. WINDOWS CLEAN-UP
function Cleanup-Windows {
    Step 'Flush TEMP folders'
    $tempFolders = "$env:TEMP", "C:\Windows\Temp"
    foreach ($folder in $tempFolders) {
        if (Test-Path $folder) {
            Get-ChildItem $folder -Recurse -Force -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Step 'Flush Windows Update download cache'
    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    $wuPath = 'C:\Windows\SoftwareDistribution\Download'
    if (Test-Path $wuPath) {
        Remove-Item -Recurse -Force "$wuPath\*" -ErrorAction SilentlyContinue
    }
    Start-Service wuauserv -ErrorAction SilentlyContinue

    Step 'Trim WinSxS (modern builds only)'
    $buildNumber = [Environment]::OSVersion.Version.Build
    if ($buildNumber -ge 14393) {
        Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null
    }

    Step 'Clear event logs protected logs silently skipped'
    $allLogs = wevtutil el
    foreach ($logName in $allLogs) { 
        $clearCmd = "wevtutil cl `"$logName`""
        cmd /c "$clearCmd 2>nul"
    }
}

# 4. VIRTIO Latest
function Install-VirtioDrivers {
    $uninstallPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    $installed = Get-ItemProperty $uninstallPath -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'VirtIO.*Guest.*Tools' }
    
    if ($installed) {
        Step 'VirtIO Guest-Tools already installed skipping'
        return
    }

    Step 'Download VirtIO Guest-Tools (Latest)'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    if ([Environment]::Is64BitOperatingSystem) { 
        $arch = 'x64' 
    } else { 
        $arch = 'x86' 
    }
    
    $msiPath = "$env:TEMP\virtio-win-gt-$arch.msi"
    
    # Use the latest-virtio folder for the most recent version
    $primaryUrl = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/virtio-win-gt-$arch.msi"
    # Fallback to stable-virtio as backup
    $backupUrl = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win-gt-$arch.msi"

    Step "Downloading from: $primaryUrl"
    try {
        Invoke-WebRequest $primaryUrl -OutFile $msiPath -UseBasicParsing -ErrorAction Stop
        Step "Download successful"
    }
    catch {
        Step 'Primary URL failed, trying backup URL'
        try {
            Invoke-WebRequest $backupUrl -OutFile $msiPath -UseBasicParsing -ErrorAction Stop
            Step "Download successful from backup"
        }
        catch {
            throw "Failed to download VirtIO drivers from both URLs. Error: $_"
        }
    }

    # Verify the MSI file exists and has content
    if (!(Test-Path $msiPath)) {
        throw "VirtIO MSI file was not downloaded successfully"
    }
    
    $fileSize = (Get-Item $msiPath).Length
    Step "MSI file size: $([math]::Round($fileSize/1MB, 2)) MB"
    
    if ($fileSize -lt 1MB) {
        throw "Downloaded MSI file appears to be corrupt (too small)"
    }

    Step 'Installing VirtIO Guest-Tools silently'
    $msiArgs = "/i `"$msiPath`" /qn /norestart /l*v `"$env:TEMP\virtio-install.log`""
    $proc = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
    $exitCode = $proc.ExitCode
    
    if ($exitCode -eq 0) {
        Step 'VirtIO Guest-Tools installed successfully'
    }
    elseif ($exitCode -eq 3010) {
        Step 'VirtIO Guest-Tools installed successfully (reboot required)'
    }
    else {
        throw "VirtIO installer failed with exit code $exitCode. Check $env:TEMP\virtio-install.log for details"
    }
}

# 5. CLOUDBASE-INIT
function Install-CloudInit {
    $svcExists = $null
    try {
        $svcExists = Get-Service cloudbase-init -ErrorAction Stop
    }
    catch {
        # Service does not exist, continue
    }
    
    if ($svcExists) {
        Step 'Cloudbase-Init already installed skipping'
        return
    }

    Step 'Download Cloudbase-Init MSI'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    if ([Environment]::Is64BitOperatingSystem) { 
        $arch = 'x64' 
    } else { 
        $arch = 'x86' 
    }
    
    $msiPath = "$env:TEMP\CloudbaseInit_$arch.msi"
    $cbUrl1 = "https://www.cloudbase.it/downloads/CloudbaseInitSetup_Stable_$arch.msi"
    $cbUrl2 = "https://github.com/cloudbase/cloudbase-init/releases/latest/download/CloudbaseInitSetup_$arch.msi"

    try {
        Invoke-WebRequest $cbUrl1 -OutFile $msiPath -UseBasicParsing -ErrorAction Stop
    }
    catch {
        Step 'Primary mirror failed trying GitHub'
        try {
            Invoke-WebRequest $cbUrl2 -OutFile $msiPath -UseBasicParsing -ErrorAction Stop
        }
        catch {
            throw "Failed to download Cloudbase-Init from both sources"
        }
    }

    Step 'Install Cloudbase-Init silently'
    $cbArgs = "/i", "`"$msiPath`"", "/qn", "/norestart", "RUN_CLOUDBASEINIT_SERVICE=1", "SYSPREP_DISABLED=1"
    $proc = Start-Process msiexec.exe -ArgumentList $cbArgs -Wait -PassThru
    $exitCode = $proc.ExitCode
    if ($exitCode -ne 0) {
        throw "Cloudbase-Init installer exited with code $exitCode"
    }

    Step 'Configure Cloudbase-Init for CloudStack metadata'
    $cbDir = "$env:ProgramFiles\Cloudbase Solutions\Cloudbase-Init\conf"
    $cbConf = "$cbDir\cloudbase-init.conf"
    
    if (!(Test-Path $cbDir)) {
        New-Item -ItemType Directory -Path $cbDir -Force | Out-Null
    }
    
    # Create config content as array of lines
    $configLines = @(
        '[DEFAULT]',
        'username              = Administrator',
        'inject_user_password  = true',
        'first_logon_behaviour = no',
        'metadata_services     = cloudbaseinit.metadata.services.cloudstack.CloudStack',
        'plugins               = cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin,cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin,cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin,cloudbaseinit.plugins.common.userdata.UserDataPlugin'
    )
    
    # Write config file
    $configLines | Out-File -FilePath $cbConf -Encoding ASCII -Force

    Set-Service cloudbase-init -StartupType Automatic
    Start-Service cloudbase-init -ErrorAction SilentlyContinue
    Step 'Cloudbase-Init configured and ready'
}

# 6. UNATTEND.XML
function Write-Unattend {
    Step 'Write unattend.xml (preserves VirtIO after Sysprep)'
    
    if ([Environment]::Is64BitOperatingSystem) { 
        $cpuArch = 'amd64' 
    } else { 
        $cpuArch = 'x86' 
    }
    
    # Build XML line by line to avoid here-string issues
    $xmlLines = @(
        '<?xml version="1.0" encoding="utf-8"?>',
        '<unattend xmlns="urn:schemas-microsoft-com:unattend">',
        '  <settings pass="generalize">',
        '    <component name="Microsoft-Windows-PnpSysprep"',
        "               processorArchitecture=`"$cpuArch`"",
        '               publicKeyToken="31bf3856ad364e35"',
        '               versionScope="nonSxS"',
        '               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">',
        '      <PersistAllDeviceInstalls>true</PersistAllDeviceInstalls>',
        '    </component>',
        '  </settings>',
        '</unattend>'
    )
    
    # Write XML file
    $xmlLines | Out-File -FilePath 'C:\unattend.xml' -Encoding UTF8 -Force
}

# 7. MAIN EXECUTION
try {
    Write-Host ""
    Write-Host "=== CloudStack Windows Guest Preparation Starting ===" -ForegroundColor Green
    Write-Host ""
    
    Optimize-OS
    Fix-Pagefile
    Cleanup-Windows
    Install-VirtioDrivers
    Install-CloudInit
    Write-Unattend
    
    Write-Host ""
    Write-Host "=== CloudStack Windows Guest Preparation Complete ===" -ForegroundColor Green
    Step 'Prep complete - reboot once, then sysprep with:'
    Write-Host '   %windir%\System32\Sysprep\Sysprep.exe /generalize /oobe /shutdown /unattend:C:\unattend.xml' -ForegroundColor Yellow
    Write-Host ""
} 
catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Stack Trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace
    exit 1
} 
finally {
    Stop-Transcript
    Write-Host "Log saved to: $log" -ForegroundColor Gray
}
