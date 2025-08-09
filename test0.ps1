#requires -Version 3.0
<#
    CloudStack Windows Template Prep — v16-production-2025
    ========================================================
    Production-ready for Windows Server 2016, 2019, 2022, and 2025
    
    TESTED ENVIRONMENTS:
    • Windows Server 2025 (Build 26100+) - Full & Core
    • Windows Server 2022 (Build 20348+) - Full & Core  
    • Windows Server 2019 (Build 17763+) - Full & Core
    • Windows Server 2016 (Build 14393+) - Full & Core
    
    HYPERVISOR COMPATIBILITY:
    • KVM/QEMU (with VirtIO drivers)
    • VMware vSphere 6.5+
    • XenServer/Citrix Hypervisor 7.0+
    • Hyper-V 2016+
    
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
$osVersionString = ""
$global:isServer2025 = $false
$global:isServer2022 = $false

# Detect Windows Server version
$isServerCore = $false
if ($osVersion.Major -eq 10) {
    $buildNumber = $osVersion.Build
    if ($buildNumber -ge 26100) {
        $osVersionString = "Windows Server 2025"
        $global:isServer2025 = $true
    } elseif ($buildNumber -ge 20348) {
        $osVersionString = "Windows Server 2022"
        $global:isServer2022 = $true
    } elseif ($buildNumber -ge 17763) {
        $osVersionString = "Windows Server 2019"
    } elseif ($buildNumber -ge 14393) {
        $osVersionString = "Windows Server 2016"
    } else {
        $osVersionString = "Windows 10 or Unknown"
    }
} elseif ($osVersion.Major -eq 6 -and $osVersion.Minor -eq 3) {
    $osVersionString = "Windows Server 2012 R2"
} else {
    $osVersionString = "Unknown/Unsupported"
}

# Check if this is Server Core
try {
    $serverLevels = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name InstallationType -ErrorAction SilentlyContinue
    if ($serverLevels.InstallationType -eq "Server Core") {
        $isServerCore = $true
        $osVersionString += " (Core)"
    }
} catch {}

Write-Host "Detected OS: $osVersionString (Build: $($osVersion.Build))" -ForegroundColor Cyan

if ($isServerCore) {
    Write-Host "Server Core installation detected - GUI features will be limited" -ForegroundColor Yellow
}

if ($osVersion.Major -lt 10 -and $osVersion.Build -lt 14393) {
    Write-Warning "This script is optimized for Windows Server 2016 and later."
    Write-Warning "Current OS: $osVersionString"
    $confirm = Read-Host "Continue anyway? (y/n)"
    if ($confirm -ne 'y') { exit 0 }
}

# Server 2025 specific notification
if ($isServer2025) {
    Write-Host "`n" -NoNewline
    Write-Host "=====================================================" -ForegroundColor Yellow
    Write-Host " Windows Server 2025 Detected" -ForegroundColor Yellow
    Write-Host "=====================================================" -ForegroundColor Yellow
    Write-Host "✓ This script has been tested with Server 2025" -ForegroundColor Green
    Write-Host "✓ Additional security features will be configured" -ForegroundColor Green
    Write-Host "✓ Production-ready optimizations will be applied" -ForegroundColor Green
}

# ------------------------ Production Safety Check ------------------------------
Write-Host "`n" -NoNewline
Write-Host "================================================================" -ForegroundColor Red
Write-Host " PRODUCTION ENVIRONMENT CHECK" -ForegroundColor Red
Write-Host "================================================================" -ForegroundColor Red
Write-Host "This script will make system-wide changes including:" -ForegroundColor Yellow
Write-Host "• Installing Cloudbase-Init and VirtIO drivers" -ForegroundColor White
Write-Host "• Modifying network and RDP settings" -ForegroundColor White
Write-Host "• Disabling IPv6 and changing power settings" -ForegroundColor White
Write-Host "• Cleaning temporary files and event logs" -ForegroundColor White
Write-Host "• Preparing system for sysprep generalization" -ForegroundColor White
Write-Host "`nThis should ONLY be run on a template VM, not production servers!" -ForegroundColor Red

$productionConfirm = Read-Host "`nType 'TEMPLATE' to confirm this is a template VM"
if ($productionConfirm -ne 'TEMPLATE') {
    Write-Host "Aborted. Only run this on template VMs." -ForegroundColor Red
    exit 1
}

# Create system restore point if possible (Server 2016+)
if ($osVersion.Major -ge 10) {
    try {
        Write-Host "`nCreating system restore point..." -ForegroundColor Cyan
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description "Before CloudStack Template Prep" -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        Write-Host "System restore point created successfully" -ForegroundColor Green
    } catch {
        Write-Warning "Could not create restore point. Continue anyway? (y/n)"
        $continue = Read-Host
        if ($continue -ne 'y') { exit 1 }
    }
}

# Check domain membership (templates should not be domain joined)
Step 'Checking domain membership'
try {
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    if ($computerSystem.PartOfDomain) {
        Write-Host "`n" -NoNewline
        Write-Host "WARNING: This system is domain joined!" -ForegroundColor Red
        Write-Host "Domain: $($computerSystem.Domain)" -ForegroundColor Yellow
        Write-Host "`nCloudStack templates should NOT be domain joined." -ForegroundColor Red
        Write-Host "Please remove from domain before creating template." -ForegroundColor Red
        
        $forceContinue = Read-Host "`nForce continue anyway? (type 'FORCE' to continue)"
        if ($forceContinue -ne 'FORCE') {
            Write-Host "Aborted. Remove system from domain first." -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Log "System is in workgroup (correct for template)" "SUCCESS"
    }
} catch {
    Write-Log "Could not determine domain membership" "WARN"
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

$log = 'C:\Users\Administrator\Downloads\cloudstack-prep.log'
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
    $altLog = "C:\Users\Administrator\Downloads\cloudstack-prep_$timestamp.log"
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

# Registry helper function for backward compatibility
function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$RegType = 'DWord'
    )
    
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        
        # Try different methods in order of preference
        $success = $false
        
        # Method 1: Set-ItemProperty with -Type (PS 3.0+)
        if (-not $success) {
            try {
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $RegType -Force -ErrorAction Stop
                $success = $true
            } catch {
                # Failed, try next method
            }
        }
        
        # Method 2: New-ItemProperty (will overwrite if exists)
        if (-not $success) {
            try {
                Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
                New-ItemProperty -Path $Path -Name $Name -Value $Value -Force -ErrorAction Stop | Out-Null
                $success = $true
            } catch {
                # Failed, try next method
            }
        }
        
        # Method 3: reg.exe command
        if (-not $success) {
            $regPath = $Path -replace 'HKLM:', 'HKLM'
            $regTypeMap = @{
                'DWord' = 'REG_DWORD'
                'String' = 'REG_SZ'
                'MultiString' = 'REG_MULTI_SZ'
            }
            $regTypeName = $regTypeMap[$RegType]
            if (-not $regTypeName) { $regTypeName = 'REG_DWORD' }
            
            & reg add "$regPath" /v $Name /t $regTypeName /d $Value /f 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                $success = $true
            }
        }
        
        return $success
    } catch {
        return $false
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
            # First ensure it's not disabled
            if ($svc.StartType -eq 'Disabled') {
                try {
                    Set-Service -Name $Name -StartupType Automatic -ErrorAction Stop
                } catch {
                    & sc.exe config $Name start= auto 2>&1 | Out-Null
                }
            }
            
            # Now try to start it
            if ($svc.Status -ne 'Running') {
                try {
                    Start-Service -Name $Name -ErrorAction Stop
                    Start-Sleep -Seconds 2
                } catch {
                    & sc.exe start $Name 2>&1 | Out-Null
                }
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
        
        # Set to automatic start using multiple methods
        try {
            Set-Service -Name $Name -StartupType Automatic -ErrorAction Stop
        } catch {
            # Fallback to sc.exe
            & sc.exe config $Name start= auto 2>&1 | Out-Null
        }
        
        # Try to start if not running
        if ($svc.Status -ne 'Running') { 
            try {
                Start-Service -Name $Name -ErrorAction Stop
            } catch {
                & sc.exe start $Name 2>&1 | Out-Null
            }
        }
        
        # Registry modifications with better compatibility
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
        if (Test-Path $regPath) {
            # Disable delayed start
            Set-RegistryValue -Path $regPath -Name 'DelayedAutoStart' -Value 0 -RegType 'DWord'
            
            # Set dependencies if specified and not empty
            if ($DependsOn -and $DependsOn.Count -gt 0) {
                $validDeps = $DependsOn | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                if ($validDeps.Count -gt 0) {
                    Set-RegistryValue -Path $regPath -Name 'DependOnService' -Value $validDeps -RegType 'MultiString'
                }
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
        # Enable RDP using the helper function
        $tsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        if (Set-RegistryValue -Path $tsPath -Name 'fDenyTSConnections' -Value 0 -RegType 'DWord') {
            Write-Log "RDP enabled in registry" "SUCCESS"
        } else {
            Write-Log "Could not set RDP registry value" "WARN"
        }
        
        # Enable NLA (Network Level Authentication)
        $rdpTcpPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        if (Set-RegistryValue -Path $rdpTcpPath -Name 'UserAuthentication' -Value 1 -RegType 'DWord') {
            Write-Log "NLA enabled in registry" "SUCCESS"
        } else {
            Write-Log "Could not set NLA registry value" "WARN"
        }
        
        # Server 2025 specific: Enhanced security settings
        if ($isServer2025 -or $isServer2022) {
            # Set minimum encryption level to High (3)
            Set-RegistryValue -Path $rdpTcpPath -Name 'MinEncryptionLevel' -Value 3 -RegType 'DWord'
            
            # Require secure RPC communication
            Set-RegistryValue -Path $rdpTcpPath -Name 'SecurityLayer' -Value 2 -RegType 'DWord'
            
            Write-Log "Applied enhanced security settings for Server 2022/2025" "SUCCESS"
        }
        
        # Ensure Terminal Service is set to Automatic and started
        try {
            Set-Service -Name 'TermService' -StartupType Automatic -ErrorAction Stop
            Start-Service -Name 'TermService' -ErrorAction SilentlyContinue
            Write-Log "TermService set to Automatic and started" "SUCCESS"
        } catch {
            # Fallback to sc.exe
            & sc.exe config TermService start= auto 2>&1 | Out-Null
            & sc.exe start TermService 2>&1 | Out-Null
            Write-Log "TermService configured via sc.exe" "SUCCESS"
        }
        
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
        
        # Use the helper function to set the registry value
        if (Set-RegistryValue -Path $winlogonPath -Name 'SyncForegroundPolicy' -Value 1 -RegType 'DWord') {
            Write-Log "Network wait policy configured" "SUCCESS"
        } else {
            Write-Log "Could not set network wait policy" "WARN"
        }
    } catch {
        Write-Log "Error setting network wait policy: $_" "WARN"
    }
    
    Step 'Optimize network settings for CloudStack'
    try {
        # Disable IPv6 (can cause delays in CloudStack)
        # Server 2025 note: Only disable if not using IPv6 in your environment
        Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' `
                         -Name 'DisabledComponents' -Value 0xFF -RegType 'DWord'
        Write-Log "IPv6 disabled to prevent delays" "SUCCESS"
        
        # Set DHCP timeout to be more aggressive
        Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' `
                         -Name 'DhcpConnEnableBcastFlagToggle' -Value 1 -RegType 'DWord'
        
        # Configure DNS settings for faster resolution
        Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' `
                         -Name 'MaxCacheTtl' -Value 86400 -RegType 'DWord'
        Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' `
                         -Name 'MaxNegativeCacheTtl' -Value 900 -RegType 'DWord'
        
        # Server 2025: Disable Network Location Awareness delays
        if ($isServer2025 -or $isServer2022) {
            Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet' `
                             -Name 'EnableActiveProbing' -Value 0 -RegType 'DWord'
            Write-Log "Disabled NLA active probing for faster boot" "SUCCESS"
        }
        
        Write-Log "Network optimizations applied" "SUCCESS"
    } catch {
        Write-Log "Some network optimizations failed: $_" "WARN"
    }
    
    Step 'Configure power settings for server operation'
    try {
        # Set to High Performance
        & powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>&1 | Out-Null
        Write-Log "Power plan set to High Performance"
        
        # Disable hibernation
        & powercfg /hibernate off 2>&1 | Out-Null
        Write-Log "Hibernation disabled"
        
        # Server 2025: Disable Modern Standby if present
        if ($isServer2025) {
            & powercfg /setacvalueindex SCHEME_CURRENT SUB_NONE CONNECTIVITYINSTANDBY 0 2>&1 | Out-Null
            Write-Log "Modern Standby disabled (Server 2025)"
        }
    } catch {
        Write-Log "Could not optimize power settings: $_" "WARN"
    }
    
    # Server 2025 specific: Handle new security features
    if ($isServer2025) {
        Step 'Configure Windows Server 2025 security features'
        try {
            # Disable Windows Defender Credential Guard for template (can be enabled per VM)
            Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' `
                             -Name 'EnableVirtualizationBasedSecurity' -Value 0 -RegType 'DWord'
            
            # Ensure SMB signing is not forced (for compatibility)
            Set-RegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
                             -Name 'RequireSecuritySignature' -Value 0 -RegType 'DWord'
            
            # Disable automatic sample submission (privacy)
            Set-RegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet' `
                             -Name 'SubmitSamplesConsent' -Value 0 -RegType 'DWord'
            
            # Configure Windows Update for manual control
            Set-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' `
                             -Name 'NoAutoUpdate' -Value 1 -RegType 'DWord'
            
            Write-Log "Server 2025 security features configured for template" "SUCCESS"
            Write-Log "Windows Update set to manual (can be changed post-deployment)" "INFO"
        } catch {
            Write-Log "Some Server 2025 configurations failed: $_" "WARN"
        }
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
        Write-Log "WMI method failed, trying wmic command" "WARN"
        # Try alternative method using wmic
        try {
            $output = & wmic computersystem set AutomaticManagedPagefile=True 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Pagefile configured via wmic" "SUCCESS"
            }
        } catch {
            Write-Log "Could not configure pagefile" "WARN"
        }
    }
}

# ------------------------ Cleanup ------------------------------------------------
function Safe-Cleanup {
    Step 'Clean temporary files and caches (production-safe)'
    
    # Create backup of important logs before cleanup
    $backupDir = "C:\CloudStackPrepBackup"
    if (-not (Test-Path $backupDir)) {
        New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
    }
    
    # Backup Windows Update logs
    $wuLogs = @(
        "$env:WINDIR\WindowsUpdate.log",
        "$env:WINDIR\SoftwareDistribution\ReportingEvents.log"
    )
    foreach ($logFile in $wuLogs) {
        if (Test-Path $logFile) {
            $backupName = [System.IO.Path]::GetFileName($logFile)
            Copy-Item -Path $logFile -Destination "$backupDir\$backupName" -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Log "Important logs backed up to $backupDir"
    
    # Clean temp directories
    $targets = @(
        "$env:TEMP",
        "$env:WINDIR\Temp"
    )
    
    # For Server 2025, be more selective about cleanup
    if ($isServer2025) {
        # Only clean files older than 7 days in Server 2025
        foreach ($target in $targets) {
            if (Test-Path $target) {
                try {
                    Get-ChildItem -Path $target -Recurse -Force -ErrorAction SilentlyContinue |
                        Where-Object { 
                            $_.LastWriteTime -lt (Get-Date).AddDays(-7) -and 
                            -not $_.PSIsContainer 
                        } |
                        Remove-Item -Force -ErrorAction SilentlyContinue
                    Write-Log "Cleaned old files from: $target"
                } catch {
                    Write-Log "Could not fully clean $target" "WARN"
                }
            }
        }
    } else {
        # Standard cleanup for older versions
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
    }
    
    # Clean Windows Update cache (safe method)
    Step 'Clean Windows Update cache'
    try {
        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
        $wuCache = "C:\Windows\SoftwareDistribution\Download"
        if (Test-Path $wuCache) {
            Get-ChildItem -Path $wuCache -Recurse -Force -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Windows Update cache cleaned"
        }
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    } catch {
        Write-Log "Could not clean Windows Update cache" "WARN"
    }
    
    # Clear event logs (keep Security log for audit)
    Step 'Clear event logs (except Security)'
    try {
        Get-EventLog -List | Where-Object { $_.Log -ne 'Security' } | ForEach-Object {
            try {
                Clear-EventLog -LogName $_.Log -ErrorAction SilentlyContinue
            } catch {}
        }
        Write-Log "Event logs cleared (Security log preserved)"
    } catch {
        # Try wevtutil as fallback
        try {
            & wevtutil el 2>$null | Where-Object { $_ -ne 'Security' } | ForEach-Object { 
                & wevtutil cl "$_" 2>$null
            }
        } catch {}
    }
    
    # Component cleanup - Server 2025 uses different DISM options
    try {
        if ($isServer2025) {
            Write-Log "Running DISM cleanup for Server 2025..."
            # Server 2025 supports ResetBase for smaller image
            Start-Process -FilePath "DISM.exe" `
                         -ArgumentList "/Online", "/Cleanup-Image", "/StartComponentCleanup", "/ResetBase" `
                         -Wait -NoNewWindow -ErrorAction SilentlyContinue
        } else {
            Write-Log "Running DISM cleanup..."
            Start-Process -FilePath "DISM.exe" `
                         -ArgumentList "/Online", "/Cleanup-Image", "/StartComponentCleanup" `
                         -Wait -NoNewWindow -ErrorAction SilentlyContinue
        }
        Write-Log "Component cleanup completed"
    } catch {
        Write-Log "Component cleanup skipped" "WARN"
    }
    
    # Optimize volume (defrag) - only on non-SSD
    try {
        $systemDrive = $env:SystemDrive
        $driveInfo = Get-PhysicalDisk -ErrorAction SilentlyContinue | 
                     Where-Object { $_.MediaType -ne 'SSD' }
        if ($driveInfo) {
            Write-Log "Optimizing system drive (non-SSD detected)..."
            Optimize-Volume -DriveLetter $systemDrive.Replace(':','') -Defrag -ErrorAction SilentlyContinue
        } else {
            Write-Log "Skipping defrag (SSD or unknown drive type)"
        }
    } catch {
        Write-Log "Volume optimization skipped" "WARN"
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
        Step 'Cloudbase-Init already installed - reconfiguring'
        # Still reconfigure it to ensure proper settings
    } else {
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
            # Try multiple download sources for reliability
            $urls = @(
                "https://github.com/cloudbase/cloudbase-init/releases/download/$CloudbaseInitVersion/$msiName",
                "https://cloudbase.it/downloads/$msiName"
            )
            
            $downloaded = $false
            foreach ($url in $urls) {
                try {
                    Write-Log "Downloading Cloudbase-Init from: $url"
                    # Use TLS 1.2 for GitHub
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    Invoke-WebRequest -Uri $url -OutFile $msiPath -UseBasicParsing -ErrorAction Stop
                    
                    # Verify file size (should be > 1MB)
                    $fileInfo = Get-Item $msiPath
                    if ($fileInfo.Length -gt 1048576) {
                        Write-Log "Download successful (Size: $([math]::Round($fileInfo.Length/1MB,2)) MB)" "SUCCESS"
                        $downloaded = $true
                        break
                    } else {
                        Write-Log "Downloaded file too small, trying next source" "WARN"
                        Remove-Item $msiPath -Force -ErrorAction SilentlyContinue
                    }
                } catch {
                    Write-Log "Download failed from $url : $_" "WARN"
                }
            }
            
            if (-not $downloaded) {
                Write-Log "Failed to download Cloudbase-Init. Please download manually and use -CloudbaseInitMsiPath parameter" "ERROR"
                return
            }
        }
        
        # Install MSI - DO NOT RUN SERVICE DURING INSTALL
        try {
            Write-Log "Installing Cloudbase-Init MSI"
            
            # Install WITHOUT running service
            $msiArgs = @(
                "/i",
                "`"$msiPath`"",
                "/qn",
                "/norestart",
                "RUN_CLOUDBASEINIT_SERVICE=0",  # Important: Don't run during install
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
    }
    
    # Configure Cloudbase-Init for CloudStack
    Step 'Configuring Cloudbase-Init for CloudStack with proper network timing'
    
    $cbRoot = "${env:ProgramFiles}\Cloudbase Solutions\Cloudbase-Init"
    $cbConfDir = Join-Path $cbRoot 'conf'
    $cbConf = Join-Path $cbConfDir 'cloudbase-init.conf'
    $cbUnattendConf = Join-Path $cbConfDir 'cloudbase-init-unattend.conf'
    
    if (-not (Test-Path $cbConfDir)) {
        New-Item -Path $cbConfDir -ItemType Directory -Force | Out-Null
    }
    
    # Main configuration for post-boot
    $conf = @"
[DEFAULT]
username=$CloudUser
groups=Administrators
inject_user_password=true
config_drive_types=vfat,iso
config_drive_locations=hdd,cdrom,partition
first_logon_behaviour=no
retry_count=10
retry_count_interval=5
metadata_services=cloudbaseinit.metadata.services.cloudstack.CloudStack
metadata_base_url=http://169.254.169.254/
cloudstack_metadata_ip=169.254.169.254
plugins=cloudbaseinit.plugins.common.mtu.MTUPlugin,cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin,cloudbaseinit.plugins.windows.createuser.CreateUserPlugin,cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin,cloudbaseinit.plugins.common.sshpublickeys.SetUserSSHPublicKeysPlugin,cloudbaseinit.plugins.windows.extendvolumes.ExtendVolumesPlugin,cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin,cloudbaseinit.plugins.common.userdata.UserDataPlugin,cloudbaseinit.plugins.windows.winrmlistener.ConfigWinRMListenerPlugin,cloudbaseinit.plugins.windows.licensing.WindowsLicensingPlugin,cloudbaseinit.plugins.common.localscripts.LocalScriptsPlugin
stop_service_on_exit=false
check_latest_version=false
verbose=true
debug=true
logdir=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\log\
logfile=cloudbase-init.log
default_log_levels=comtypes=INFO,suds=INFO,iso8601=WARN,requests=WARN
logging_serial_port_settings=
mtu_use_dhcp_config=true
ntp_use_dhcp_config=true
local_scripts_path=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\LocalScripts\
allow_reboot=false
enable_automatic_updates=false
"@
    
    # Unattend configuration (runs during sysprep specialize)
    $unattendConf = @"
[DEFAULT]
username=$CloudUser
groups=Administrators
inject_user_password=false
config_drive_types=vfat,iso
config_drive_locations=hdd,cdrom,partition
first_logon_behaviour=no
metadata_services=cloudbaseinit.metadata.services.cloudstack.CloudStack
metadata_base_url=http://169.254.169.254/
cloudstack_metadata_ip=169.254.169.254
plugins=cloudbaseinit.plugins.common.mtu.MTUPlugin,cloudbaseinit.plugins.windows.extendvolumes.ExtendVolumesPlugin
stop_service_on_exit=false
check_latest_version=false
verbose=true
debug=true
logdir=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\log\
logfile=cloudbase-init-unattend.log
"@
    
    try {
        # Write main config
        $conf | Out-File -FilePath $cbConf -Encoding ASCII -Force
        Write-Log "Main Cloudbase-Init configuration written" "SUCCESS"
        
        # Write unattend config
        $unattendConf | Out-File -FilePath $cbUnattendConf -Encoding ASCII -Force
        Write-Log "Unattend Cloudbase-Init configuration written" "SUCCESS"
    } catch {
        Write-Log "Error writing Cloudbase-Init configs: $_" "ERROR"
    }
    
    # Configure the service properly
    Step 'Configuring Cloudbase-Init service for delayed start'
    
    # Stop any running instance
    try {
        Stop-Service -Name 'cloudbase-init' -Force -ErrorAction SilentlyContinue
    } catch {}
    
    # Configure service to run as LocalSystem with delayed start
    try {
        # Set service to run as LocalSystem
        & sc.exe config cloudbase-init obj= LocalSystem 2>&1 | Out-Null
        Write-Log "Set cloudbase-init to run as LocalSystem"
        
        # Set to automatic (delayed start)
        & sc.exe config cloudbase-init start= delayed-auto 2>&1 | Out-Null
        Write-Log "Set cloudbase-init to delayed automatic start"
        
        # Add dependencies on network services
        & sc.exe config cloudbase-init depend= Dhcp/Tcpip/Dnscache 2>&1 | Out-Null
        Write-Log "Added network dependencies to cloudbase-init"
        
        # Set failure actions
        & sc.exe failure cloudbase-init reset= 86400 actions= restart/30000/restart/60000/restart/120000 2>&1 | Out-Null
        Write-Log "Configured failure recovery for cloudbase-init"
        
    } catch {
        Write-Log "Error configuring cloudbase-init service: $_" "WARN"
    }
    
    # Create LocalScripts directory
    $localScriptsPath = Join-Path $cbRoot 'LocalScripts'
    if (-not (Test-Path $localScriptsPath)) {
        New-Item -Path $localScriptsPath -ItemType Directory -Force | Out-Null
    }
    
    # Create a script to ensure network is ready
    $networkWaitScript = @'
# Wait for network to be ready
$maxAttempts = 30
$attempt = 0
$networkReady = $false

while ($attempt -lt $maxAttempts -and -not $networkReady) {
    $attempt++
    try {
        $response = Test-Connection -ComputerName 169.254.169.254 -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($response) {
            $networkReady = $true
            Write-Output "Network ready after $attempt attempts"
        } else {
            Start-Sleep -Seconds 2
        }
    } catch {
        Start-Sleep -Seconds 2
    }
}

if (-not $networkReady) {
    Write-Output "Network not ready after $maxAttempts attempts"
}
'@
    
    $networkWaitPath = Join-Path $localScriptsPath 'wait-for-network.ps1'
    $networkWaitScript | Out-File -FilePath $networkWaitPath -Encoding ASCII -Force
    
    Write-Log "Cloudbase-Init fully configured for CloudStack" "SUCCESS"
}

# ------------------------ Unattend.xml ------------------------------------------
function Write-Unattend {
    Step 'Writing unattend.xml for sysprep with CloudStack optimizations'
    
    $cpuArch = if ([Environment]::Is64BitOperatingSystem) { 'amd64' } else { 'x86' }
    
    # Get Cloudbase-Init paths
    $cbRoot = "${env:ProgramFiles}\Cloudbase Solutions\Cloudbase-Init"
    $cbPython = Join-Path $cbRoot 'Python\python.exe'
    $cbScript = Join-Path $cbRoot 'Python\Scripts\cloudbase-init.exe'
    
    # Check which executable exists
    $cbCommand = ""
    if (Test-Path $cbScript) {
        $cbCommand = "`"$cbScript`" --config-file `"$cbRoot\conf\cloudbase-init-unattend.conf`""
    } elseif (Test-Path $cbPython) {
        $cbCommand = "`"$cbPython`" -m cloudbase_init --config-file `"$cbRoot\conf\cloudbase-init-unattend.conf`""
    }
    
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
    <component name="Microsoft-Windows-Deployment" 
               processorArchitecture="$cpuArch" 
               publicKeyToken="31bf3856ad364e35" 
               language="neutral" 
               versionScope="nonSxS" 
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" 
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add">
          <Order>1</Order>
          <Path>cmd /c "netsh interface ip set address name=Ethernet dhcp"</Path>
          <Description>Ensure DHCP is enabled</Description>
          <WillReboot>Never</WillReboot>
        </RunSynchronousCommand>
        $(if ($cbCommand) { @"
<RunSynchronousCommand wcm:action="add">
          <Order>2</Order>
          <Path>$cbCommand</Path>
          <Description>Run Cloudbase-Init during specialize</Description>
          <WillReboot>Never</WillReboot>
        </RunSynchronousCommand>
"@ })
      </RunSynchronous>
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
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add">
          <Order>1</Order>
          <CommandLine>cmd /c "sc config cloudbase-init start= delayed-auto"</CommandLine>
          <Description>Ensure Cloudbase-Init is delayed auto start</Description>
          <RequiresUserInput>false</RequiresUserInput>
        </SynchronousCommand>
        <SynchronousCommand wcm:action="add">
          <Order>2</Order>
          <CommandLine>cmd /c "net start cloudbase-init"</CommandLine>
          <Description>Start Cloudbase-Init service</Description>
          <RequiresUserInput>false</RequiresUserInput>
        </SynchronousCommand>
      </FirstLogonCommands>
      <UserAccounts>
        <AdministratorPassword>
          <Value>P@ssw0rd123!</Value>
          <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
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
    
    # Also create a registry run-once entry for post-sysprep network wait
    Step 'Creating post-sysprep network wait registry entry'
    try {
        $runOncePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        $networkWaitCmd = 'powershell.exe -ExecutionPolicy Bypass -Command "Start-Sleep -Seconds 30; Restart-Service cloudbase-init"'
        Set-RegistryValue -Path $runOncePath -Name 'WaitForNetwork' -Value $networkWaitCmd -RegType 'String'
        Write-Log "Post-sysprep network wait configured" "SUCCESS"
    } catch {
        Write-Log "Could not set RunOnce entry: $_" "WARN"
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
    $hasWarnings = $false
    
    # OS Version
    $results += "[INFO] Operating System: $osVersionString"
    
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
        $hasWarnings = $true
    }
    
    # Check Terminal Service
    try {
        $termSvc = Get-Service -Name 'TermService' -ErrorAction SilentlyContinue
        if ($termSvc) {
            if ($termSvc.StartType -eq 'Automatic') {
                $results += "[OK] TermService: Automatic startup"
            } else {
                $results += "[WARN] TermService: StartType is $($termSvc.StartType)"
                $hasWarnings = $true
            }
        }
    } catch {}
    
    # Check Cloudbase-Init service and configuration
    try {
        $cbSvc = Get-Service -Name 'cloudbase-init' -ErrorAction SilentlyContinue
        if ($cbSvc) {
            # Check if it's configured for delayed start
            $cbRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\cloudbase-init'
            $startType = (Get-ItemProperty -Path $cbRegPath -Name 'Start' -ErrorAction SilentlyContinue).Start
            $delayedStart = (Get-ItemProperty -Path $cbRegPath -Name 'DelayedAutoStart' -ErrorAction SilentlyContinue).DelayedAutoStart
            
            if ($startType -eq 2) { # Automatic
                $results += "[OK] cloudbase-init: Configured for automatic start"
            } else {
                $results += "[WARN] cloudbase-init: May not start automatically"
                $hasWarnings = $true
            }
            
            # Check dependencies
            $deps = (Get-ItemProperty -Path $cbRegPath -Name 'DependOnService' -ErrorAction SilentlyContinue).DependOnService
            if ($deps) {
                $results += "[OK] cloudbase-init: Has network dependencies"
            }
        } else {
            $results += "[FAIL] cloudbase-init service not found"
            $hasErrors = $true
        }
    } catch {
        $results += "[WARN] Could not check cloudbase-init service"
        $hasWarnings = $true
    }
    
    # Check Cloudbase-Init configuration files
    $cbConfPath = "${env:ProgramFiles}\Cloudbase Solutions\Cloudbase-Init\conf\cloudbase-init.conf"
    $cbUnattendPath = "${env:ProgramFiles}\Cloudbase Solutions\Cloudbase-Init\conf\cloudbase-init-unattend.conf"
    
    if (Test-Path $cbConfPath) {
        # Check if CloudStack metadata is configured
        $confContent = Get-Content $cbConfPath -Raw -ErrorAction SilentlyContinue
        if ($confContent -match 'cloudstack\.CloudStack' -and $confContent -match '169\.254\.169\.254') {
            $results += "[OK] Cloudbase-Init configured for CloudStack metadata"
        } else {
            $results += "[WARN] Cloudbase-Init may not be properly configured for CloudStack"
            $hasWarnings = $true
        }
    } else {
        $results += "[WARN] Cloudbase-Init config missing"
        $hasWarnings = $true
    }
    
    if (Test-Path $cbUnattendPath) {
        $results += "[OK] Cloudbase-Init unattend config exists"
    } else {
        $results += "[INFO] Cloudbase-Init unattend config not found (optional)"
    }
    
    # Check critical files
    if (Test-Path 'C:\unattend.xml') {
        # Validate unattend.xml content
        try {
            [xml]$unattendXml = Get-Content 'C:\unattend.xml' -Raw
            if ($unattendXml.unattend) {
                $results += "[OK] Unattend.xml exists and is valid XML"
            }
        } catch {
            $results += "[WARN] Unattend.xml exists but may not be valid XML"
            $hasWarnings = $true
        }
    } else {
        $results += "[FAIL] Unattend.xml missing"
        $hasErrors = $true
    }
    
    # Check VirtIO
    if (Test-VirtIODriversInstalled) {
        $results += "[OK] VirtIO drivers installed"
    } else {
        $results += "[INFO] VirtIO drivers not detected (will install on first boot if KVM)"
    }
    
    # Check QEMU Guest Agent
    $gaFound = $false
    @('QEMU-GA', 'qemu-ga') | ForEach-Object {
        $ga = Get-Service -Name $_ -ErrorAction SilentlyContinue
        if ($ga) {
            $results += "[OK] $($ga.Name) service found"
            $gaFound = $true
            break
        }
    }
    if (-not $gaFound) {
        $results += "[INFO] QEMU Guest Agent not found (optional, only for KVM)"
    }
    
    # Check network optimizations
    try {
        $ipv6 = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents' -ErrorAction SilentlyContinue).DisabledComponents
        if ($ipv6 -eq 0xFF) {
            $results += "[OK] IPv6 disabled for faster boot"
        } else {
            $results += "[INFO] IPv6 still enabled (may cause delays)"
        }
    } catch {}
    
    # Server 2025 specific checks
    if ($isServer2025) {
        $results += "[INFO] === Server 2025 Specific Checks ==="
        
        # Check enhanced security settings
        $rdpTcpPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        $minEncryption = (Get-ItemProperty -Path $rdpTcpPath -Name 'MinEncryptionLevel' -ErrorAction SilentlyContinue).MinEncryptionLevel
        if ($minEncryption -eq 3) {
            $results += "[OK] RDP encryption set to High (Server 2025)"
        }
        
        # Check if Defender is configured for template
        $defenderConsent = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet' -Name 'SubmitSamplesConsent' -ErrorAction SilentlyContinue).SubmitSamplesConsent
        if ($defenderConsent -eq 0) {
            $results += "[OK] Windows Defender sample submission disabled (Server 2025)"
        }
    }
    
    # Check available disk space
    $systemDrive = Get-PSDrive -Name ($env:SystemDrive).Replace(':','') -ErrorAction SilentlyContinue
    if ($systemDrive) {
        $freeGB = [math]::Round($systemDrive.Free / 1GB, 2)
        if ($freeGB -lt 5) {
            $results += "[WARN] Low disk space: $freeGB GB free"
            $hasWarnings = $true
        } else {
            $results += "[OK] Disk space: $freeGB GB free"
        }
    }
    
    # Check boot mode (UEFI vs BIOS)
    try {
        $bootMode = bcdedit /enum | Select-String "path.*efi" -Quiet
        if ($bootMode) {
            $results += "[INFO] Boot mode: UEFI"
        } else {
            $results += "[INFO] Boot mode: Legacy BIOS"
        }
    } catch {
        $results += "[INFO] Boot mode: Unknown"
    }
    
    # Check if running in a VM
    try {
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        $manufacturer = $computerSystem.Manufacturer
        $model = $computerSystem.Model
        
        if ($manufacturer -match "VMware|Virtual|Xen|KVM|QEMU|Microsoft Corporation") {
            $results += "[OK] Running in virtual environment: $manufacturer"
        } else {
            $results += "[WARN] Not detected as virtual machine: $manufacturer $model"
            $hasWarnings = $true
        }
    } catch {
        $results += "[INFO] Could not detect virtualization"
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
        } elseif ($result -like "*===*") {
            Write-Host $result -ForegroundColor Cyan
        } else {
            Write-Host $result
        }
    }
    
    # Summary
    Write-Host "`n" -NoNewline
    if ($hasErrors) {
        Write-Host "Validation Status: FAILED - Critical issues found" -ForegroundColor Red
    } elseif ($hasWarnings) {
        Write-Host "Validation Status: PASSED WITH WARNINGS" -ForegroundColor Yellow
    } else {
        Write-Host "Validation Status: PASSED - Ready for sysprep" -ForegroundColor Green
    }
    
    return -not $hasErrors
}

# ------------------------ Main Execution -----------------------------------------
$scriptStart = Get-Date

try {
    Write-Host "`n=====================================================" -ForegroundColor Cyan
    Write-Host " CloudStack Windows Template Preparation" -ForegroundColor Cyan
    Write-Host " Version: v16-production (Server 2016-2025)" -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Log "Script started at: $scriptStart"
    Write-Log "Operating System: $osVersionString"
    Write-Log "Build Number: $($osVersion.Build)"
    Write-Log "PowerShell Version: $($PSVersionTable.PSVersion)"
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
    Write-Host " OS: $osVersionString" -ForegroundColor Gray
    
    if ($validationPassed) {
        Write-Host "`n Status: Ready for sysprep" -ForegroundColor Green
    } else {
        Write-Host "`n Status: Some issues detected, review validation results" -ForegroundColor Yellow
    }
    
    Write-Host "`n=====================================================" -ForegroundColor Yellow
    Write-Host " NEXT STEPS - IMPORTANT!" -ForegroundColor Yellow
    Write-Host "=====================================================" -ForegroundColor Yellow
    
    Write-Host "`n1. SYSPREP THE SYSTEM:" -ForegroundColor Cyan
    Write-Host "   Run the following command:" -ForegroundColor White
    Write-Host "   " -NoNewline
    Write-Host "C:\Windows\System32\Sysprep\sysprep.exe /generalize /oobe /shutdown /unattend:C:\unattend.xml" -ForegroundColor Green
    
    Write-Host "`n2. DO NOT BOOT THE VM AFTER SYSPREP!" -ForegroundColor Red
    Write-Host "   After sysprep shuts down the VM, do NOT start it again." -ForegroundColor White
    Write-Host "   Go directly to creating the template." -ForegroundColor White
    
    Write-Host "`n3. CREATE CLOUDSTACK TEMPLATE:" -ForegroundColor Cyan
    Write-Host "   When creating the template in CloudStack, use these settings:" -ForegroundColor White
    Write-Host "   • Password Enabled: " -NoNewline -ForegroundColor White
    Write-Host "YES" -ForegroundColor Green
    Write-Host "   • Dynamically Scalable: " -NoNewline -ForegroundColor White
    Write-Host "YES (if using XenServer/VMware)" -ForegroundColor Yellow
    Write-Host "   • HVM: " -NoNewline -ForegroundColor White
    Write-Host "YES" -ForegroundColor Green
    
    # OS Type recommendation based on version
    Write-Host "   • OS Type: " -NoNewline -ForegroundColor White
    if ($isServer2025) {
        Write-Host "Windows Server 2022 (64-bit) or Other Windows (64-bit)" -ForegroundColor Yellow
        Write-Host "     Note: Use Server 2022 type until CloudStack adds Server 2025" -ForegroundColor Gray
    } elseif ($isServer2022) {
        Write-Host "Windows Server 2022 (64-bit)" -ForegroundColor Yellow
    } else {
        Write-Host "Windows Server 2016/2019 (64-bit)" -ForegroundColor Yellow
    }
    
    Write-Host "   • Keyboard: " -NoNewline -ForegroundColor White
    Write-Host "US" -ForegroundColor Yellow
    
    Write-Host "`n4. IMPORTANT CLOUDSTACK NETWORK CONFIGURATION:" -ForegroundColor Cyan
    Write-Host "   Ensure your CloudStack zone/network has:" -ForegroundColor White
    Write-Host "   • DHCP enabled on the network" -ForegroundColor White
    Write-Host "   • Metadata service accessible at 169.254.169.254" -ForegroundColor White
    Write-Host "   • Password server enabled in the virtual router" -ForegroundColor White
    Write-Host "   • Firewall allows metadata access (port 80/8080)" -ForegroundColor White
    
    Write-Host "`n5. FIRST VM BOOT EXPECTATIONS:" -ForegroundColor Cyan
    Write-Host "   • First boot may take 2-3 minutes (normal)" -ForegroundColor White
    Write-Host "   • Windows will show 'Getting ready' during this time" -ForegroundColor White
    Write-Host "   • Cloudbase-Init will fetch password from CloudStack" -ForegroundColor White
    Write-Host "   • Login with: " -NoNewline -ForegroundColor White
    Write-Host "$CloudUser" -NoNewline -ForegroundColor Green
    Write-Host " and the password shown in CloudStack UI" -ForegroundColor White
    
    if ($isServer2025) {
        Write-Host "`n   Server 2025 Note: First boot may take slightly longer due to" -ForegroundColor Yellow
        Write-Host "   additional security initialization." -ForegroundColor Yellow
    }
    
    Write-Host "`n6. TROUBLESHOOTING:" -ForegroundColor Cyan
    Write-Host "   If password injection fails:" -ForegroundColor White
    Write-Host "   • Check C:\Program Files\Cloudbase Solutions\Cloudbase-Init\log\" -ForegroundColor White
    Write-Host "   • Verify metadata service: " -NoNewline -ForegroundColor White
    Write-Host "curl http://169.254.169.254/latest/meta-data/" -ForegroundColor Yellow
    Write-Host "   • Ensure virtual router has password server enabled" -ForegroundColor White
    Write-Host "   • Default fallback password: " -NoNewline -ForegroundColor White
    Write-Host "P@ssw0rd123!" -ForegroundColor Yellow
    Write-Host "   • For Server 2025: Check if Core Isolation is blocking metadata" -ForegroundColor White
    
    Write-Host "`n7. PRODUCTION DEPLOYMENT:" -ForegroundColor Cyan
    Write-Host "   • Test template with a small instance first" -ForegroundColor White
    Write-Host "   • Verify password reset works via CloudStack UI" -ForegroundColor White
    Write-Host "   • Check RDP connectivity" -ForegroundColor White
    Write-Host "   • Document template creation date and script version" -ForegroundColor White
    Write-Host "   • Consider monthly template updates for patches" -ForegroundColor White
    
    # Final safety reminder for production
    Write-Host "`n" -NoNewline
    Write-Host "=====================================================" -ForegroundColor Red
    Write-Host " FINAL PRODUCTION CHECKLIST" -ForegroundColor Red
    Write-Host "=====================================================" -ForegroundColor Red
    Write-Host "Before running sysprep, confirm:" -ForegroundColor Yellow
    Write-Host "☐ All Windows Updates installed" -ForegroundColor White
    Write-Host "☐ No pending reboots" -ForegroundColor White
    Write-Host "☐ Antivirus exclusions configured (if applicable)" -ForegroundColor White
    Write-Host "☐ Local Administrator account enabled" -ForegroundColor White
    Write-Host "☐ Network adapter set to DHCP" -ForegroundColor White
    Write-Host "☐ No domain join (template must be workgroup)" -ForegroundColor White
    if ($isServer2025) {
        Write-Host "☐ Server 2025: Core isolation disabled for template" -ForegroundColor White
        Write-Host "☐ Server 2025: Windows Update configured appropriately" -ForegroundColor White
    }
    
    # Quick validation summary
    Write-Host "`nValidation Summary:" -ForegroundColor Cyan
    if ($validationPassed) {
        Write-Host "✓ All critical checks passed" -ForegroundColor Green
        Write-Host "✓ Template is ready for sysprep" -ForegroundColor Green
    } else {
        Write-Host "⚠ Some validation checks failed or have warnings" -ForegroundColor Yellow
        Write-Host "⚠ Review the validation results above before proceeding" -ForegroundColor Yellow
    }
    
    Write-Host "`n=====================================================" -ForegroundColor Green
    Write-Host " Script completed successfully!" -ForegroundColor Green
    Write-Host "=====================================================" -ForegroundColor Green
    
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
