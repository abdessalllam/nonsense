#requires -Version 5.1
<#
    CloudStack Windows Template Prep (Server 2016 → 2025) — v13-fixed-verified
    --------------------------------------------------------------------------
    Double-checked version with additional error handling and compatibility fixes
    
    Parameters:
      -CloudUser 'Administrator'
      -CloudbaseInitVersion '1.1.6'
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

# ------------------------ Version Check -----------------------------------------
$osVersion = [System.Environment]::OSVersion.Version
if ($osVersion.Major -lt 10) {
    Write-Warning "This script is designed for Windows Server 2016 (10.0) and later. Current version: $($osVersion.Major).$($osVersion.Minor)"
    $confirm = Read-Host "Continue anyway? (y/n)"
    if ($confirm -ne 'y') { exit 0 }
}

# ------------------------ Self-elevate if not Admin ----------------------------
function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

if (-not (Test-IsAdmin)) {
    Write-Host "Elevation required. Relaunching as Administrator..." -ForegroundColor Yellow
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    
    foreach ($k in $PSBoundParameters.Keys) {
        $val = $PSBoundParameters[$k]
        if ($val -is [System.Management.Automation.SwitchParameter]) {
            if ($val.IsPresent) { 
                $argList += "-$k" 
            }
        } elseif ($null -ne $val -and "$val".Length -gt 0) {
            $argList += "-$k"
            $argList += "`"$val`""
        }
    }
    
    try {
        Start-Process powershell -ArgumentList $argList -Verb RunAs -Wait
        exit 0
    } catch {
        Write-Error "User declined elevation or elevation failed. Exiting."
        exit 1
    }
}

# ------------------------ Setup and Logging -------------------------------------
$ErrorActionPreference = 'Continue'
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {
    Write-Warning "Could not set TLS 1.2. Downloads might fail on older systems."
}

$log = 'C:\cloudstack-prep.log'
$transcriptStarted = $false

# Try to start transcript
try { 
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
} catch {}

try { 
    Start-Transcript -Path $log -Append -ErrorAction Stop | Out-Null
    $transcriptStarted = $true 
} catch {
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $altLog = "C:\cloudstack-prep_$timestamp.log"
    try { 
        Start-Transcript -Path $altLog -Append -ErrorAction Stop | Out-Null
        $transcriptStarted = $true
        $log = $altLog
    } catch {
        Write-Warning "Could not start transcript logging. Continuing without logging."
    }
}

# ------------------------ Helper Functions --------------------------------------
function Step {
    param([string]$m)
    Write-Host "`n>> $m" -ForegroundColor Cyan
}

function Write-Log {
    param(
        [string]$Message, 
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Level] $Message"
    
    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "WARN"  { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        default { Write-Host $logMessage }
    }
}

# Try to import LocalAccounts module silently
$localAccountsAvailable = $false
try { 
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction Stop 2>$null
    $localAccountsAvailable = $true
} catch {
    # Module not available, will use fallback methods
}

# ------------------------ Service Management Functions -------------------------
function Try-StartService {
    param([string]$Name)
    
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    
    try {
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($svc) {
            if ($svc.StartType -eq 'Disabled') {
                Set-Service -Name $Name -StartupType Automatic -ErrorAction SilentlyContinue
            }
            if ($svc.Status -ne 'Running') {
                Start-Service -Name $Name -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
            return $true
        }
    } catch {
        Write-Log "Could not start service $Name : $_" "WARN"
    }
    return $false
}

function Ensure-ServiceAutoStart {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string[]]$DependsOn = @()
    )
    
    if ([string]::IsNullOrWhiteSpace($Name)) { return }
    
    try {
        # Check if service exists
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if (-not $svc) { 
            Write-Log "Service $Name does not exist" "WARN"
            return 
        }
        
        # Set to automatic start
        Set-Service -Name $Name -StartupType Automatic -ErrorAction SilentlyContinue
        
        # Try to start if not running
        if ($svc.Status -ne 'Running') { 
            Start-Service -Name $Name -ErrorAction SilentlyContinue 
        }
        
        # Registry modifications
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
        if (Test-Path $regPath) {
            try {
                # Disable delayed start
                Set-ItemProperty -Path $regPath -Name 'DelayedAutoStart' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue
                
                # Set dependencies if specified and not empty
                if ($DependsOn -and $DependsOn.Count -gt 0) {
                    $validDeps = $DependsOn | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                    if ($validDeps.Count -gt 0) {
                        Set-ItemProperty -Path $regPath -Name 'DependOnService' -Value $validDeps -PropertyType MultiString -Force -ErrorAction SilentlyContinue
                    }
                }
            } catch {
                # Registry modification failed, but service exists so continue
            }
        }
        
        Write-Log "Service $Name configured for automatic start" "SUCCESS"
    } catch {
        Write-Log "Error configuring service $Name : $_" "WARN"
    }
}

# ------------------------ Detection Functions -----------------------------------
function Test-CloudbaseInitInstalled {
    try {
        # Check for service
        $svc = Get-Service -Name 'cloudbase-init' -ErrorAction SilentlyContinue
        if (-not $svc) { return $false }
        
        # Check for installation in Program Files
        $searchPaths = @("${env:ProgramFiles}\Cloudbase Solutions\Cloudbase-Init")
        
        # Only add x86 path if it exists and is different from ProgramFiles
        if ($env:ProgramFiles -and ${env:ProgramFiles(x86)}) {
            if (${env:ProgramFiles} -ne ${env:ProgramFiles(x86)}) {
                $searchPaths += "${env:ProgramFiles(x86)}\Cloudbase Solutions\Cloudbase-Init"
            }
        }
        
        foreach ($basePath in $searchPaths) {
            if (Test-Path $basePath) {
                # Check for executables
                $exe1 = Join-Path $basePath 'Python\Scripts\cloudbase-init.exe'
                $exe2 = Join-Path $basePath 'bin\OpenStackService.exe'
                if ((Test-Path $exe1) -or (Test-Path $exe2)) {
                    return $true
                }
            }
        }
    } catch {
        Write-Log "Error checking Cloudbase-Init: $_" "WARN"
    }
    return $false
}

function Test-VirtIODriversInstalled {
    try {
        # Method 1: Check WMI for Red Hat drivers
        try {
            $drivers = @(Get-WmiObject Win32_PnPSignedDriver -ErrorAction Stop | 
                        Where-Object { 
                            $_.DriverProviderName -like '*Red Hat*' -or 
                            $_.DeviceName -like '*VirtIO*' -or
                            $_.Description -like '*VirtIO*'
                        })
            if ($drivers.Count -gt 0) { return $true }
        } catch {
            # WMI query failed, try alternative method
        }
        
        # Method 2: Check for VirtIO services in registry
        $svcNames = @('NetKVM','vioscsi','viostor','vioserial','vioinput','viorng','qemufwcfg','qemupciserial','pvpanic','Balloon')
        foreach ($svcName in $svcNames) {
            if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName") { 
                return $true 
            }
        }
    } catch {
        Write-Log "Error checking VirtIO drivers: $_" "WARN"
    }
    return $false
}

function Test-QemuGAInstalled {
    $gaNames = @('QEMU-GA', 'qemu-ga', 'QEMU Guest Agent')
    foreach ($name in $gaNames) {
        try {
            if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
                return $true
            }
        } catch {
            # Service check failed, continue
        }
    }
    return $false
}

# ------------------------ OS Optimization ---------------------------------------
function Optimize-OS {
    Step 'Enable RDP + NLA and open firewall'
    
    try {
        # Create registry path if it doesn't exist
        $tsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        if (-not (Test-Path $tsPath)) {
            New-Item -Path $tsPath -Force | Out-Null
        }
        
        # Enable RDP
        Set-ItemProperty -Path $tsPath -Name 'fDenyTSConnections' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue
        
        # Enable NLA
        $rdpTcpPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        if (-not (Test-Path $rdpTcpPath)) {
            New-Item -Path $rdpTcpPath -Force | Out-Null
        }
        Set-ItemProperty -Path $rdpTcpPath -Name 'UserAuthentication' -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue
        
        Write-Log "RDP and NLA enabled" "SUCCESS"
        
        # Start Terminal Service
        Try-StartService -Name 'TermService'
        
        # Configure firewall - try multiple methods
        $firewallConfigured = $false
        
        # Method 1: PowerShell cmdlets
        try {
            Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction Stop
            $firewallConfigured = $true
            Write-Log "Firewall rules enabled via PowerShell" "SUCCESS"
        } catch {
            # Method 2: netsh command
            try {
                $result = & netsh advfirewall firewall set rule group="remote desktop" new enable=Yes 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $firewallConfigured = $true
                    Write-Log "Firewall rules enabled via netsh" "SUCCESS"
                }
            } catch {
                Write-Log "Could not configure firewall for RDP" "WARN"
            }
        }
    } catch {
        Write-Log "Error configuring RDP: $_" "ERROR"
    }
    
    Step 'Configure network wait at startup'
    try {
        $winlogonPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $pathParts = $winlogonPath -split '\\'
        $currentPath = $pathParts[0]
        
        # Create each part of the path
        for ($i = 1; $i -lt $pathParts.Length; $i++) {
            $currentPath = "$currentPath\$($pathParts[$i])"
            if (-not (Test-Path $currentPath)) {
                New-Item -Path $currentPath -Force | Out-Null
            }
        }
        
        Set-ItemProperty -Path $winlogonPath -Name 'SyncForegroundPolicy' -Value 1 -PropertyType DWord -Force
        Write-Log "Network wait policy configured" "SUCCESS"
    } catch {
        Write-Log "Error setting network wait policy: $_" "WARN"
    }
}

# ------------------------ Pagefile Configuration --------------------------------
function Fix-Pagefile {
    Step 'Configure pagefile as system-managed'
    try {
        $cs = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
        if ($null -ne $cs) {
            if ($cs.AutomaticManagedPagefile -ne $true) {
                $cs.AutomaticManagedPagefile = $true
                $result = $cs.Put()
                Write-Log "Pagefile set to system-managed" "SUCCESS"
            } else {
                Write-Log "Pagefile already system-managed"
            }
        }
    } catch {
        Write-Log "Error configuring pagefile: $_" "WARN"
        # Try alternative method using wmic
        try {
            & wmic computersystem set AutomaticManagedPagefile=True 2>&1 | Out-Null
        } catch {}
    }
}

# ------------------------ Cleanup ------------------------------------------------
function Safe-Cleanup {
    Step 'Clean temporary files and caches'
    
    $targets = @(
        "$env:TEMP",
        "$env:WINDIR\Temp",
        "C:\Windows\SoftwareDistribution\Download"
    )
    
    foreach ($target in $targets) {
        if (Test-Path $target) {
            try {
                Get-ChildItem -Path $target -Recurse -Force -ErrorAction SilentlyContinue | 
                    Where-Object { -not $_.PSIsContainer -or (Get-ChildItem $_.FullName -Force -ErrorAction SilentlyContinue).Count -eq 0 } |
                    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Cleaned: $target"
            } catch {
                Write-Log "Could not fully clean $target" "WARN"
            }
        }
    }
    
    # Clear event logs
    Step 'Clear event logs'
    try {
        Get-EventLog -List | ForEach-Object {
            try {
                Clear-EventLog -LogName $_.Log -ErrorAction SilentlyContinue
            } catch {}
        }
        Write-Log "Event logs cleared"
    } catch {
        # Try wevtutil as fallback
        try {
            & wevtutil el 2>$null | ForEach-Object { 
                & wevtutil cl "$_" 2>$null
            }
        } catch {}
    }
    
    # Component cleanup
    try {
        Write-Log "Running DISM cleanup (this may take a few minutes)..."
        Start-Process -FilePath "DISM.exe" `
                     -ArgumentList "/Online", "/Cleanup-Image", "/StartComponentCleanup" `
                     -Wait -NoNewWindow -ErrorAction SilentlyContinue
        Write-Log "Component cleanup completed"
    } catch {
        Write-Log "Component cleanup skipped" "WARN"
    }
}

# ------------------------ VirtIO Installation ------------------------------------
function Install-VirtIO {
    if ($SkipVirtIO) { 
        Step 'Skipping VirtIO installation (requested)'
        return 
    }
    
    # Check if already installed
    $driversPresent = Test-VirtIODriversInstalled
    $gaPresent = Test-QemuGAInstalled
    
    if ($driversPresent -and $gaPresent) {
        Step 'VirtIO drivers and QEMU-GA already installed'
        Ensure-ServiceAutoStart -Name 'QEMU-GA'
        Ensure-ServiceAutoStart -Name 'qemu-ga'
        return
    }
    
    Step 'Installing VirtIO Guest Tools'
    
    $arch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    $msiName = "virtio-win-gt-$arch.msi"
    $msiPath = if ($VirtIOMsiPath -and (Test-Path $VirtIOMsiPath)) { 
        $VirtIOMsiPath 
    } else { 
        Join-Path $env:TEMP $msiName 
    }
    
    # Download if needed
    if (-not (Test-Path $msiPath)) {
        Write-Log "VirtIO MSI not found locally, attempting download..."
        $urls = @(
            "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/$msiName",
            "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/$msiName"
        )
        
        $downloaded = $false
        foreach ($url in $urls) {
            try {
                Write-Log "Trying: $url"
                Invoke-WebRequest -Uri $url -OutFile $msiPath -UseBasicParsing -ErrorAction Stop
                $downloaded = $true
                Write-Log "Download successful" "SUCCESS"
                break
            } catch {
                Write-Log "Download failed from this URL" "WARN"
            }
        }
        
        if (-not $downloaded) {
            Write-Log "Could not download VirtIO MSI. You may need to install manually." "ERROR"
            return
        }
    }
    
    # Install MSI
    if (Test-Path $msiPath) {
        try {
            Write-Log "Installing VirtIO MSI: $msiPath"
            $msiArgs = @(
                "/i",
                "`"$msiPath`"",
                "/qn",
                "/norestart",
                "/l*v",
                "`"$env:TEMP\virtio-install.log`""
            )
            
            $proc = Start-Process -FilePath "msiexec.exe" `
                                 -ArgumentList $msiArgs `
                                 -Wait -PassThru -NoNewWindow
            
            if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {
                Write-Log "VirtIO MSI installed successfully" "SUCCESS"
            } else {
                Write-Log "VirtIO MSI installer returned code: $($proc.ExitCode)" "WARN"
            }
        } catch {
            Write-Log "Error installing VirtIO MSI: $_" "ERROR"
        }
    }
    
    # Try pnputil from ISO if provided
    if ($VirtIOIsoDrive -and (Test-Path $VirtIOIsoDrive)) {
        try {
            Write-Log "Staging drivers from ISO: $VirtIOIsoDrive"
            $infFiles = Get-ChildItem -Path $VirtIOIsoDrive -Filter "*.inf" -Recurse -ErrorAction SilentlyContinue
            
            if ($infFiles.Count -gt 0) {
                & pnputil.exe /add-driver "$VirtIOIsoDrive\*.inf" /subdirs /install 2>&1 | Out-Null
                Write-Log "Drivers staged from ISO"
            }
        } catch {
            Write-Log "Could not stage drivers from ISO" "WARN"
        }
        
        # Try to install GA from ISO
        if (-not $gaPresent) {
            $gaPaths = @(
                "$VirtIOIsoDrive\guest-agent\qemu-ga-x86_64.msi",
                "$VirtIOIsoDrive\guest-agent\qemu-ga-x64.msi",
                "$VirtIOIsoDrive\qemu-ga-x64.msi"
            )
            
            foreach ($gaPath in $gaPaths) {
                if (Test-Path $gaPath) {
                    try {
                        Write-Log "Installing QEMU-GA from: $gaPath"
                        $proc = Start-Process -FilePath "msiexec.exe" `
                                            -ArgumentList "/i", "`"$gaPath`"", "/qn", "/norestart" `
                                            -Wait -PassThru -NoNewWindow
                        if ($proc.ExitCode -eq 0) {
                            Write-Log "QEMU-GA installed successfully" "SUCCESS"
                            break
                        }
                    } catch {
                        Write-Log "Could not install QEMU-GA: $_" "WARN"
                    }
                }
            }
        }
    }
    
    # Ensure GA service is set to automatic
    Ensure-ServiceAutoStart -Name 'QEMU-GA'
    Ensure-ServiceAutoStart -Name 'qemu-ga'
}

# ------------------------ Cloudbase-Init Installation ----------------------------
function Install-CloudbaseInit {
    if ($SkipCloudbaseInit) { 
        Step 'Skipping Cloudbase-Init installation (requested)'
        return 
    }
    
    if (Test-CloudbaseInitInstalled) {
        Step 'Cloudbase-Init already installed'
        Ensure-ServiceAutoStart -Name 'cloudbase-init'
        return
    }
    
    Step "Installing Cloudbase-Init ($CloudbaseInitVersion)"
    
    $arch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    $vUnderscore = $CloudbaseInitVersion -replace '\.', '_'
    $msiName = "CloudbaseInitSetup_{0}_{1}.msi" -f $vUnderscore, $arch
    $msiPath = if ($CloudbaseInitMsiPath -and (Test-Path $CloudbaseInitMsiPath)) { 
        $CloudbaseInitMsiPath 
    } else { 
        Join-Path $env:TEMP $msiName 
    }
    
    # Download if needed
    if (-not (Test-Path $msiPath)) {
        $url = "https://github.com/cloudbase/cloudbase-init/releases/download/$CloudbaseInitVersion/$msiName"
        try {
            Write-Log "Downloading Cloudbase-Init from: $url"
            Invoke-WebRequest -Uri $url -OutFile $msiPath -UseBasicParsing -ErrorAction Stop
            Write-Log "Download successful" "SUCCESS"
        } catch {
            Write-Log "Failed to download Cloudbase-Init: $_" "ERROR"
            return
        }
    }
    
    # Install MSI
    try {
        Write-Log "Installing Cloudbase-Init MSI"
        
        # Install with service creation enabled
        $msiArgs = @(
            "/i",
            "`"$msiPath`"",
            "/qn",
            "/norestart",
            "RUN_CLOUDBASEINIT_SERVICE=1",
            "USERNAME=$CloudUser",
            "INJECTMETADATAPASSWORD=1"
        )
        
        $proc = Start-Process -FilePath "msiexec.exe" `
                            -ArgumentList $msiArgs `
                            -Wait -PassThru -NoNewWindow
        
        if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {
            Write-Log "Cloudbase-Init installed successfully" "SUCCESS"
        } else {
            Write-Log "Cloudbase-Init installer returned code: $($proc.ExitCode)" "WARN"
        }
    } catch {
        Write-Log "Error installing Cloudbase-Init: $_" "ERROR"
        return
    }
    
    # Configure Cloudbase-Init
    Step 'Configuring Cloudbase-Init for CloudStack'
    
    $cbRoot = "${env:ProgramFiles}\Cloudbase Solutions\Cloudbase-Init"
    $cbConfDir = Join-Path $cbRoot 'conf'
    $cbConf = Join-Path $cbConfDir 'cloudbase-init.conf'
    
    if (-not (Test-Path $cbConfDir)) {
        New-Item -Path $cbConfDir -ItemType Directory -Force | Out-Null
    }
    
    # Create configuration with proper formatting
    $pluginList = @(
        'cloudbaseinit.plugins.common.mtu.MTUPlugin',
        'cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin',
        'cloudbaseinit.plugins.windows.createuser.CreateUserPlugin',
        'cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin',
        'cloudbaseinit.plugins.windows.licensing.WindowsLicensingPlugin',
        'cloudbaseinit.plugins.common.sshpublickeys.SetUserSSHPublicKeysPlugin',
        'cloudbaseinit.plugins.windows.extendvolumes.ExtendVolumesPlugin',
        'cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin',
        'cloudbaseinit.plugins.common.localscripts.LocalScriptsPlugin'
    )
    
    $conf = @"
[DEFAULT]
username=$CloudUser
groups=Administrators
inject_user_password=true
first_logon_behaviour=no
metadata_services=cloudbaseinit.metadata.services.cloudstack.CloudStack
plugins=$($pluginList -join ',')
verbose=true
debug=true
logdir=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\log\
logfile=cloudbase-init.log
default_log_levels=comtypes=INFO,suds=INFO,iso8601=WARN,requests=WARN
logging_serial_port_settings=
mtu_use_dhcp_config=true
ntp_use_dhcp_config=true
local_scripts_path=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\LocalScripts\
check_latest_version=false
"@
    
    try {
        # Use UTF8 without BOM
        [System.IO.File]::WriteAllText($cbConf, $conf, [System.Text.UTF8Encoding]::new($false))
        Write-Log "Cloudbase-Init configuration written" "SUCCESS"
    } catch {
        Write-Log "Error writing Cloudbase-Init config: $_" "ERROR"
    }
    
    # Ensure service is configured
    Ensure-ServiceAutoStart -Name 'cloudbase-init'
    
    # Stop the service to prevent it from running before sysprep
    try {
        Stop-Service -Name 'cloudbase-init' -Force -ErrorAction SilentlyContinue
        Write-Log "Stopped cloudbase-init service (will start after sysprep)"
    } catch {}
}

# ------------------------ Unattend.xml ------------------------------------------
function Write-Unattend {
    Step 'Writing unattend.xml for sysprep'
    
    $cpuArch = if ([Environment]::Is64BitOperatingSystem) { 'amd64' } else { 'x86' }
    
    $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="generalize">
    <component name="Microsoft-Windows-PnpSysprep" 
               processorArchitecture="$cpuArch" 
               publicKeyToken="31bf3856ad364e35" 
               language="neutral" 
               versionScope="nonSxS" 
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" 
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <PersistAllDeviceInstalls>true</PersistAllDeviceInstalls>
      <DoNotCleanUpNonPresentDevices>true</DoNotCleanUpNonPresentDevices>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" 
               processorArchitecture="$cpuArch" 
               publicKeyToken="31bf3856ad364e35" 
               language="neutral" 
               versionScope="nonSxS" 
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" 
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <ProtectYourPC>1</ProtectYourPC>
        <SkipMachineOOBE>true</SkipMachineOOBE>
        <SkipUserOOBE>true</SkipUserOOBE>
      </OOBE>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" 
               processorArchitecture="$cpuArch" 
               publicKeyToken="31bf3856ad364e35" 
               language="neutral" 
               versionScope="nonSxS" 
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" 
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <ComputerName>*</ComputerName>
    </component>
  </settings>
</unattend>
"@
    
    try {
        # Write with UTF8 encoding (with BOM for Windows compatibility)
        $xml | Out-File -FilePath 'C:\unattend.xml' -Encoding UTF8 -Force
        Write-Log "Unattend.xml written successfully" "SUCCESS"
    } catch {
        Write-Log "Error writing unattend.xml: $_" "ERROR"
    }
}

# ------------------------ Local Account Management ------------------------------
function Prepare-LocalAccount {
    if ($CloudUser -eq 'Administrator') {
        Step 'Using built-in Administrator account'
        # Ensure Administrator is enabled
        try {
            & net user Administrator /active:yes 2>&1 | Out-Null
        } catch {}
        return
    }
    
    Step "Ensuring user account '$CloudUser' exists"
    
    # Check if LocalAccounts module is available
    if ($localAccountsAvailable) {
        try {
            # Use PowerShell cmdlets
            $user = Get-LocalUser -Name $CloudUser -ErrorAction SilentlyContinue
            
            if (-not $user) {
                Write-Log "Creating user: $CloudUser"
                $params = @{
                    Name = $CloudUser
                    NoPassword = $true
                    AccountNeverExpires = $true
                    UserMayNotChangePassword = $false
                    ErrorAction = 'Stop'
                }
                New-LocalUser @params | Out-Null
                Write-Log "User created successfully" "SUCCESS"
            } else {
                if (-not $user.Enabled) {
                    Enable-LocalUser -Name $CloudUser -ErrorAction Stop
                    Write-Log "User enabled: $CloudUser" "SUCCESS"
                }
            }
            
            # Add to groups
            @('Administrators', 'Remote Desktop Users') | ForEach-Object {
                try {
                    Add-LocalGroupMember -Group $_ -Member $CloudUser -ErrorAction SilentlyContinue
                    Write-Log "Added $CloudUser to $_ group"
                } catch {
                    # Already a member or group doesn't exist
                }
            }
        } catch {
            Write-Log "Error with PowerShell user management: $_" "WARN"
            # Fall through to net user commands
        }
    } else {
        # Use net user commands as fallback
        try {
            $userExists = & net user $CloudUser 2>&1 | Select-String "User name"
            
            if (-not $userExists) {
                Write-Log "Creating user via net user: $CloudUser"
                & net user $CloudUser /add /expires:never /active:yes 2>&1 | Out-Null
            } else {
                & net user $CloudUser /active:yes 2>&1 | Out-Null
            }
            
            # Add to groups
            & net localgroup Administrators $CloudUser /add 2>&1 | Out-Null
            & net localgroup "Remote Desktop Users" $CloudUser /add 2>&1 | Out-Null
            
            Write-Log "User configured via net user" "SUCCESS"
        } catch {
            Write-Log "Error managing user via net user: $_" "WARN"
        }
    }
}

# ------------------------ Validation ---------------------------------------------
function Validate-Setup {
    Step 'Validating configuration'
    
    $results = @()
    $hasErrors = $false
    
    # Check RDP
    try {
        $rdpReg = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
        $rdpEnabled = $rdpReg.fDenyTSConnections -eq 0
        if ($rdpEnabled) {
            $results += "[OK] RDP is enabled"
        } else {
            $results += "[FAIL] RDP is not enabled"
            $hasErrors = $true
        }
    } catch {
        $results += "[WARN] Could not check RDP status"
    }
    
    # Check services
    @('TermService', 'cloudbase-init', 'QEMU-GA', 'qemu-ga') | ForEach-Object {
        $svcName = $_
        try {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc) {
                if ($svc.StartType -eq 'Automatic') {
                    $results += "[OK] $($svc.Name): Automatic startup"
                } else {
                    $results += "[WARN] $($svc.Name): StartType is $($svc.StartType)"
                }
            }
        } catch {}
    }
    
    # Check critical files
    if (Test-Path 'C:\unattend.xml') {
        $results += "[OK] Unattend.xml exists"
    } else {
        $results += "[FAIL] Unattend.xml missing"
        $hasErrors = $true
    }
    
    $cbConfPath = "${env:ProgramFiles}\Cloudbase Solutions\Cloudbase-Init\conf\cloudbase-init.conf"
    if (Test-Path $cbConfPath) {
        $results += "[OK] Cloudbase-Init config exists"
    } else {
        $results += "[WARN] Cloudbase-Init config missing"
    }
    
    # Check VirtIO
    if (Test-VirtIODriversInstalled) {
        $results += "[OK] VirtIO drivers installed"
    } else {
        $results += "[INFO] VirtIO drivers not detected (may install on first boot)"
    }
    
    # Display results
    Write-Host "`nValidation Results:" -ForegroundColor Green
    Write-Host "===================" -ForegroundColor Green
    foreach ($result in $results) {
        if ($result -like "*[OK]*") {
            Write-Host $result -ForegroundColor Green
        } elseif ($result -like "*[FAIL]*") {
            Write-Host $result -ForegroundColor Red
        } elseif ($result -like "*[WARN]*") {
            Write-Host $result -ForegroundColor Yellow
        } else {
            Write-Host $result
        }
    }
    
    return -not $hasErrors
}

# ------------------------ Main Execution -----------------------------------------
$scriptStart = Get-Date

try {
    Write-Host "`n=====================================================" -ForegroundColor Cyan
    Write-Host " CloudStack Windows Template Preparation v13-verified" -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Log "Script started at: $scriptStart"
    Write-Log "Parameters: CloudUser=$CloudUser, SkipVirtIO=$SkipVirtIO, SkipCloudbaseInit=$SkipCloudbaseInit"
    
    # Execute preparation steps
    Optimize-OS
    Fix-Pagefile
    Prepare-LocalAccount
    Install-VirtIO
    Install-CloudbaseInit
    Write-Unattend
    Safe-Cleanup
    
    # Validation
    $validationPassed = Validate-Setup
    
    $scriptEnd = Get-Date
    $duration = $scriptEnd - $scriptStart
    
    # Final message
    Write-Host "`n=====================================================" -ForegroundColor Green
    Write-Host " PREPARATION COMPLETED" -ForegroundColor Green
    Write-Host "=====================================================" -ForegroundColor Green
    Write-Host " Duration: $($duration.ToString('mm\:ss'))" -ForegroundColor Gray
    Write-Host " Log file: $log" -ForegroundColor Gray
    
    if ($validationPassed) {
        Write-Host "`n Status: Ready for sysprep" -ForegroundColor Green
    } else {
        Write-Host "`n Status: Some issues detected, review validation results" -ForegroundColor Yellow
    }
    
    Write-Host "`nNext steps:" -ForegroundColor Yellow
    Write-Host "1. Review the validation results above" -ForegroundColor Yellow
    Write-Host "2. If everything looks good, run sysprep:" -ForegroundColor Yellow
    Write-Host "`n   " -NoNewline
    Write-Host "C:\Windows\System32\Sysprep\sysprep.exe /generalize /oobe /shutdown /unattend:C:\unattend.xml" -ForegroundColor Cyan
    Write-Host "`n3. After shutdown, create CloudStack template with:" -ForegroundColor Yellow
    Write-Host "   - Password Enabled = Yes" -ForegroundColor Yellow
    Write-Host "   - Hypervisor Tools = Yes (if using XenServer/VMware)" -ForegroundColor Yellow
    
} catch {
    Write-Host "`n=====================================================" -ForegroundColor Red
    Write-Host " ERROR OCCURRED" -ForegroundColor Red
    Write-Host "=====================================================" -ForegroundColor Red
    Write-Host " Error: $($_.Exception.Message)" -ForegroundColor Red
    
    if ($_.ScriptStackTrace) {
        Write-Host "`nStack trace:" -ForegroundColor DarkGray
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    }
    
    Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
    Write-Host "1. Check the log file: $log" -ForegroundColor Yellow
    Write-Host "2. Run with -SkipVirtIO or -SkipCloudbaseInit to skip problematic components" -ForegroundColor Yellow
    Write-Host "3. Ensure you're running as Administrator" -ForegroundColor Yellow
    
    exit 1
} finally {
    if ($transcriptStarted) {
        try { 
            Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
        } catch {}
    }
}
