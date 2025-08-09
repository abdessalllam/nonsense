#requires -Version 3.0
<#
    CloudStack Template Configuration Fix
    --------------------------------------
    Fixes password injection and startup delays for CloudStack VMs
    Run this AFTER installing Cloudbase-Init and VirtIO drivers
#>

param(
    [string]$CloudUser = 'Administrator',
    [switch]$VerifyOnly
)

# Ensure running as Administrator
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "This script must run as Administrator. Exiting." -ForegroundColor Red
    exit 1
}

$ErrorActionPreference = 'Continue'

function Write-Status {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    switch ($Level) {
        "ERROR" { Write-Host "$timestamp [$Level] $Message" -ForegroundColor Red }
        "WARN"  { Write-Host "$timestamp [$Level] $Message" -ForegroundColor Yellow }
        "SUCCESS" { Write-Host "$timestamp [$Level] $Message" -ForegroundColor Green }
        "CHECK" { Write-Host "$timestamp [$Level] $Message" -ForegroundColor Cyan }
        default { Write-Host "$timestamp [$Level] $Message" }
    }
}

# ============================================================================
# CRITICAL FIX 1: Configure Cloudbase-Init for CloudStack Password Injection
# ============================================================================
function Fix-CloudbaseInitConfig {
    Write-Host "`n=== Configuring Cloudbase-Init for CloudStack ===" -ForegroundColor Cyan
    
    $cbRoot = "${env:ProgramFiles}\Cloudbase Solutions\Cloudbase-Init"
    $cbConfDir = Join-Path $cbRoot 'conf'
    $cbConf = Join-Path $cbConfDir 'cloudbase-init.conf'
    $cbUnattendConf = Join-Path $cbConfDir 'cloudbase-init-unattend.conf'
    
    if (-not (Test-Path $cbRoot)) {
        Write-Status "Cloudbase-Init not installed at expected location: $cbRoot" "ERROR"
        return $false
    }
    
    if (-not (Test-Path $cbConfDir)) {
        New-Item -Path $cbConfDir -ItemType Directory -Force | Out-Null
    }
    
    # Main configuration - this runs after sysprep
    $mainConfig = @"
[DEFAULT]
# User configuration
username=$CloudUser
groups=Administrators
inject_user_password=true
first_logon_behaviour=no

# CloudStack specific settings
metadata_services=cloudbaseinit.metadata.services.cloudstack.CloudStack
metadata_base_url=http://169.254.169.254/

# Plugins to run (order matters!)
plugins=cloudbaseinit.plugins.common.mtu.MTUPlugin,cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin,cloudbaseinit.plugins.windows.createuser.CreateUserPlugin,cloudbaseinit.plugins.common.setuserpassword.SetUserPasswordPlugin,cloudbaseinit.plugins.common.networkconfig.NetworkConfigPlugin,cloudbaseinit.plugins.windows.extendvolumes.ExtendVolumesPlugin,cloudbaseinit.plugins.common.localscripts.LocalScriptsPlugin

# Logging
verbose=true
debug=true
logdir=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\log\
logfile=cloudbase-init.log

# Network settings
mtu_use_dhcp_config=true
ntp_use_dhcp_config=true

# Performance settings
retry_count=5
retry_count_interval=5
metadata_services_retries=10
stop_service_on_exit=false
check_latest_version=false

# Local scripts path
local_scripts_path=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\LocalScripts\
"@

    # Unattend configuration - this runs during sysprep specialize pass
    $unattendConfig = @"
[DEFAULT]
# User configuration
username=$CloudUser
groups=Administrators
inject_user_password=false

# Minimal plugins for unattend phase
plugins=cloudbaseinit.plugins.common.mtu.MTUPlugin,cloudbaseinit.plugins.windows.extendvolumes.ExtendVolumesPlugin

# Logging
verbose=true
debug=true
logdir=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\log\
logfile=cloudbase-init-unattend.log

# Don't stop service after unattend phase
stop_service_on_exit=false
"@

    try {
        # Write main configuration
        [System.IO.File]::WriteAllText($cbConf, $mainConfig, [System.Text.UTF8Encoding]::new($false))
        Write-Status "Main configuration written to: $cbConf" "SUCCESS"
        
        # Write unattend configuration
        [System.IO.File]::WriteAllText($cbUnattendConf, $unattendConfig, [System.Text.UTF8Encoding]::new($false))
        Write-Status "Unattend configuration written to: $cbUnattendConf" "SUCCESS"
        
        return $true
    } catch {
        Write-Status "Error writing configuration: $_" "ERROR"
        return $false
    }
}

# ============================================================================
# CRITICAL FIX 2: Configure Service Dependencies and Startup
# ============================================================================
function Fix-ServiceConfiguration {
    Write-Host "`n=== Configuring Service Dependencies ===" -ForegroundColor Cyan
    
    # Stop cloudbase-init if running (it shouldn't run until after sysprep)
    $cbSvc = Get-Service -Name 'cloudbase-init' -ErrorAction SilentlyContinue
    if ($cbSvc) {
        if ($cbSvc.Status -eq 'Running') {
            Stop-Service -Name 'cloudbase-init' -Force -ErrorAction SilentlyContinue
            Write-Status "Stopped cloudbase-init service (will start after sysprep)" "SUCCESS"
        }
        
        # Set to Automatic (Delayed Start) with proper dependencies
        try {
            # Use sc.exe for maximum compatibility
            & sc.exe config cloudbase-init start= delayed-auto 2>&1 | Out-Null
            Write-Status "Set cloudbase-init to Automatic (Delayed Start)" "SUCCESS"
            
            # Set dependencies - wait for network and DHCP
            & sc.exe config cloudbase-init depend= Dhcp/EventLog/Dnscache 2>&1 | Out-Null
            Write-Status "Set service dependencies for network readiness" "SUCCESS"
            
            # Configure failure actions
            & sc.exe failure cloudbase-init reset= 86400 actions= restart/30000/restart/60000/restart/120000 2>&1 | Out-Null
            Write-Status "Configured service recovery options" "SUCCESS"
            
        } catch {
            Write-Status "Error configuring service: $_" "WARN"
        }
    } else {
        Write-Status "cloudbase-init service not found!" "ERROR"
        return $false
    }
    
    # Ensure QEMU Guest Agent is configured if present
    foreach ($gaSvc in @('QEMU-GA', 'qemu-ga', 'QEMU Guest Agent')) {
        $ga = Get-Service -Name $gaSvc -ErrorAction SilentlyContinue
        if ($ga) {
            & sc.exe config $gaSvc start= delayed-auto 2>&1 | Out-Null
            Write-Status "Configured $gaSvc for delayed start" "SUCCESS"
            break
        }
    }
    
    return $true
}

# ============================================================================
# CRITICAL FIX 3: Create Proper Unattend.xml for Sysprep
# ============================================================================
function Fix-UnattendXml {
    Write-Host "`n=== Creating Sysprep Unattend.xml ===" -ForegroundColor Cyan
    
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
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <PersistAllDeviceInstalls>true</PersistAllDeviceInstalls>
      <DoNotCleanUpNonPresentDevices>true</DoNotCleanUpNonPresentDevices>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Deployment" 
               processorArchitecture="$cpuArch" 
               publicKeyToken="31bf3856ad364e35" 
               language="neutral" 
               versionScope="nonSxS" 
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add">
          <Order>1</Order>
          <Description>Run Cloudbase-Init Unattend</Description>
          <Path>cmd /c ""C:\Program Files\Cloudbase Solutions\Cloudbase-Init\Python\Scripts\cloudbase-init.exe" --config-file "C:\Program Files\Cloudbase Solutions\Cloudbase-Init\conf\cloudbase-init-unattend.conf""</Path>
        </RunSynchronousCommand>
      </RunSynchronous>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" 
               processorArchitecture="$cpuArch" 
               publicKeyToken="31bf3856ad364e35" 
               language="neutral" 
               versionScope="nonSxS">
      <ComputerName>*</ComputerName>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" 
               processorArchitecture="$cpuArch" 
               publicKeyToken="31bf3856ad364e35" 
               language="neutral" 
               versionScope="nonSxS">
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
      <UserAccounts>
        <AdministratorPassword>
          <Value></Value>
          <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <TimeZone>UTC</TimeZone>
    </component>
  </settings>
</unattend>
"@

    try {
        $xml | Out-File -FilePath 'C:\unattend.xml' -Encoding UTF8 -Force
        Write-Status "Unattend.xml created at C:\unattend.xml" "SUCCESS"
        return $true
    } catch {
        Write-Status "Error creating unattend.xml: $_" "ERROR"
        return $false
    }
}

# ============================================================================
# CRITICAL FIX 4: Configure Network and Group Policy Settings
# ============================================================================
function Fix-SystemSettings {
    Write-Host "`n=== Configuring System Settings ===" -ForegroundColor Cyan
    
    # Enable Administrator account
    try {
        & net user Administrator /active:yes 2>&1 | Out-Null
        Write-Status "Administrator account enabled" "SUCCESS"
    } catch {}
    
    # Configure network to wait at startup
    try {
        & reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" /v SyncForegroundPolicy /t REG_DWORD /d 1 /f 2>&1 | Out-Null
        Write-Status "Configured network wait policy" "SUCCESS"
    } catch {}
    
    # Disable Server Manager auto-start
    try {
        & reg add "HKLM\SOFTWARE\Microsoft\ServerManager" /v DoNotOpenServerManagerAtLogon /t REG_DWORD /d 1 /f 2>&1 | Out-Null
        Write-Status "Disabled Server Manager auto-start" "SUCCESS"
    } catch {}
    
    # Set power plan to High Performance
    try {
        & powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>&1 | Out-Null
        Write-Status "Set power plan to High Performance" "SUCCESS"
    } catch {}
    
    # Disable Windows Update during OOBE
    try {
        & reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v DisablePrivacyExperience /t REG_DWORD /d 1 /f 2>&1 | Out-Null
        & reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v BypassNRO /t REG_DWORD /d 1 /f 2>&1 | Out-Null
        Write-Status "Configured OOBE settings" "SUCCESS"
    } catch {}
    
    return $true
}

# ============================================================================
# VERIFICATION: Check Everything is Properly Configured
# ============================================================================
function Verify-Configuration {
    Write-Host "`n=== Verification Checklist ===" -ForegroundColor Cyan
    
    $checks = @{
        "Cloudbase-Init Service" = $false
        "Cloudbase-Init Config" = $false
        "Cloudbase-Init Unattend Config" = $false
        "VirtIO Drivers" = $false
        "QEMU Guest Agent" = $false
        "Unattend.xml" = $false
        "Network Wait Policy" = $false
        "Administrator Account" = $false
        "RDP Enabled" = $false
    }
    
    # Check Cloudbase-Init Service
    $cbSvc = Get-Service -Name 'cloudbase-init' -ErrorAction SilentlyContinue
    if ($cbSvc) {
        $checks["Cloudbase-Init Service"] = $true
        Write-Status "Cloudbase-Init Service: $($cbSvc.Status), StartType: $($cbSvc.StartType)" "CHECK"
        
        # Check dependencies
        $deps = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\cloudbase-init" -Name DependOnService -ErrorAction SilentlyContinue).DependOnService
        if ($deps) {
            Write-Status "  Dependencies: $($deps -join ', ')" "INFO"
        }
    } else {
        Write-Status "Cloudbase-Init Service: NOT FOUND" "ERROR"
    }
    
    # Check Cloudbase-Init configurations
    $cbConf = "${env:ProgramFiles}\Cloudbase Solutions\Cloudbase-Init\conf\cloudbase-init.conf"
    if (Test-Path $cbConf) {
        $checks["Cloudbase-Init Config"] = $true
        $content = Get-Content $cbConf -ErrorAction SilentlyContinue
        if ($content -match "cloudstack") {
            Write-Status "Cloudbase-Init Config: Configured for CloudStack" "CHECK"
        } else {
            Write-Status "Cloudbase-Init Config: Found but NOT configured for CloudStack" "WARN"
        }
    } else {
        Write-Status "Cloudbase-Init Config: NOT FOUND" "ERROR"
    }
    
    $cbUnattendConf = "${env:ProgramFiles}\Cloudbase Solutions\Cloudbase-Init\conf\cloudbase-init-unattend.conf"
    if (Test-Path $cbUnattendConf) {
        $checks["Cloudbase-Init Unattend Config"] = $true
        Write-Status "Cloudbase-Init Unattend Config: Found" "CHECK"
    } else {
        Write-Status "Cloudbase-Init Unattend Config: NOT FOUND" "WARN"
    }
    
    # Check VirtIO Drivers
    $virtioDrivers = @(Get-WmiObject Win32_PnPSignedDriver -ErrorAction SilentlyContinue | 
                      Where-Object { $_.DriverProviderName -like '*Red Hat*' })
    if ($virtioDrivers.Count -gt 0) {
        $checks["VirtIO Drivers"] = $true
        Write-Status "VirtIO Drivers: $($virtioDrivers.Count) drivers installed" "CHECK"
    } else {
        # Check for VirtIO services
        $virtioServices = @('NetKVM','vioscsi','viostor','vioserial')
        $foundServices = @()
        foreach ($svc in $virtioServices) {
            if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc") {
                $foundServices += $svc
            }
        }
        if ($foundServices.Count -gt 0) {
            $checks["VirtIO Drivers"] = $true
            Write-Status "VirtIO Services: $($foundServices -join ', ')" "CHECK"
        } else {
            Write-Status "VirtIO Drivers: NOT FOUND (may install on first boot)" "WARN"
        }
    }
    
    # Check QEMU Guest Agent
    foreach ($gaSvc in @('QEMU-GA', 'qemu-ga', 'QEMU Guest Agent')) {
        $ga = Get-Service -Name $gaSvc -ErrorAction SilentlyContinue
        if ($ga) {
            $checks["QEMU Guest Agent"] = $true
            Write-Status "QEMU Guest Agent: $($ga.Status), StartType: $($ga.StartType)" "CHECK"
            break
        }
    }
    if (-not $checks["QEMU Guest Agent"]) {
        Write-Status "QEMU Guest Agent: NOT FOUND (optional)" "WARN"
    }
    
    # Check Unattend.xml
    if (Test-Path 'C:\unattend.xml') {
        $checks["Unattend.xml"] = $true
        $xmlContent = Get-Content 'C:\unattend.xml' -Raw
        if ($xmlContent -match "cloudbase-init") {
            Write-Status "Unattend.xml: Found with Cloudbase-Init integration" "CHECK"
        } else {
            Write-Status "Unattend.xml: Found but missing Cloudbase-Init integration" "WARN"
        }
    } else {
        Write-Status "Unattend.xml: NOT FOUND" "ERROR"
    }
    
    # Check Network Wait Policy
    $netWait = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name SyncForegroundPolicy -ErrorAction SilentlyContinue).SyncForegroundPolicy
    if ($netWait -eq 1) {
        $checks["Network Wait Policy"] = $true
        Write-Status "Network Wait Policy: Configured" "CHECK"
    } else {
        Write-Status "Network Wait Policy: NOT configured" "WARN"
    }
    
    # Check Administrator Account
    $adminActive = & net user Administrator 2>&1 | Select-String "Account active.*Yes"
    if ($adminActive) {
        $checks["Administrator Account"] = $true
        Write-Status "Administrator Account: Enabled" "CHECK"
    } else {
        Write-Status "Administrator Account: NOT enabled" "WARN"
    }
    
    # Check RDP
    $rdpEnabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
    if ($rdpEnabled -eq 0) {
        $checks["RDP Enabled"] = $true
        Write-Status "RDP: Enabled" "CHECK"
    } else {
        Write-Status "RDP: NOT enabled" "WARN"
    }
    
    # Summary
    Write-Host "`n=== Verification Summary ===" -ForegroundColor Cyan
    $passCount = ($checks.Values | Where-Object { $_ -eq $true }).Count
    $totalCount = $checks.Count
    
    if ($passCount -eq $totalCount) {
        Write-Status "ALL CHECKS PASSED ($passCount/$totalCount)" "SUCCESS"
        Write-Host "`n✓ System is ready for sysprep!" -ForegroundColor Green
        return $true
    } elseif ($passCount -ge ($totalCount - 2)) {
        Write-Status "MOSTLY READY ($passCount/$totalCount checks passed)" "WARN"
        Write-Host "`n⚠ System is mostly ready but review warnings above" -ForegroundColor Yellow
        return $true
    } else {
        Write-Status "NOT READY ($passCount/$totalCount checks passed)" "ERROR"
        Write-Host "`n✗ System needs configuration fixes before sysprep" -ForegroundColor Red
        return $false
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host " CloudStack Template Configuration Fix" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host " This script fixes password injection issues" -ForegroundColor White
Write-Host " and reduces startup delays for CloudStack VMs" -ForegroundColor White
Write-Host "================================================" -ForegroundColor Cyan

if ($VerifyOnly) {
    Write-Host "`nRunning in VERIFY ONLY mode..." -ForegroundColor Yellow
    $ready = Verify-Configuration
} else {
    Write-Host "`nApplying configuration fixes..." -ForegroundColor Green
    
    # Apply all fixes
    $configOk = Fix-CloudbaseInitConfig
    $serviceOk = Fix-ServiceConfiguration
    $unattendOk = Fix-UnattendXml
    $systemOk = Fix-SystemSettings
    
    # Verify everything
    Write-Host "`nVerifying configuration..." -ForegroundColor Yellow
    $ready = Verify-Configuration
}

# Final instructions
if ($ready) {
    Write-Host "`n================================================" -ForegroundColor Green
    Write-Host " CONFIGURATION COMPLETE" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
    Write-Host "`nNEXT STEPS:" -ForegroundColor Yellow
    Write-Host "1. Run sysprep to generalize the image:" -ForegroundColor White
    Write-Host "   " -NoNewline
    Write-Host "C:\Windows\System32\Sysprep\sysprep.exe /generalize /oobe /shutdown /unattend:C:\unattend.xml" -ForegroundColor Cyan
    Write-Host "`n2. After VM shuts down, create CloudStack template with:" -ForegroundColor White
    Write-Host "   • Password Enabled = Yes" -ForegroundColor White
    Write-Host "   • Password Management = Yes" -ForegroundColor White
    Write-Host "   • Hypervisor Tools = Yes (if XenServer/VMware)" -ForegroundColor White
    Write-Host "`n3. When creating instances from this template:" -ForegroundColor White
    Write-Host "   • CloudStack will inject the password" -ForegroundColor White
    Write-Host "   • VM should boot in ~2-3 minutes" -ForegroundColor White
    Write-Host "   • Password will be available in CloudStack UI" -ForegroundColor White
    Write-Host "================================================" -ForegroundColor Green
} else {
    Write-Host "`n================================================" -ForegroundColor Red
    Write-Host " CONFIGURATION NEEDS ATTENTION" -ForegroundColor Red
    Write-Host "================================================" -ForegroundColor Red
    Write-Host " Please fix the errors above and run again" -ForegroundColor Yellow
    Write-Host "================================================" -ForegroundColor Red
}

Write-Host "`nScript completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
