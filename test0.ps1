# Complete Windows Template Preparation Script for CloudStack
# Tested on: Windows Server 2016/2019/2022, Windows 10/11
# Run as Administrator

param(
    [switch]$SkipOptimization = $false,
    [switch]$SkipCleanup = $false,
    [switch]$SkipSysprep = $false,
    [switch]$DisableWindowsUpdate = $false,
    [switch]$DisableDefender = $false,
    [switch]$RemoveBloatware = $false
)

# Script configuration
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# Colors for output
function Write-Success { Write-Host $args[0] -ForegroundColor Green }
function Write-Info { Write-Host $args[0] -ForegroundColor Cyan }
function Write-Warning { Write-Host $args[0] -ForegroundColor Yellow }
function Write-Error { Write-Host $args[0] -ForegroundColor Red }

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator!"
    Write-Host "Right-click PowerShell and select 'Run as Administrator'"
    Exit 1
}

Write-Info "=========================================="
Write-Info "Windows CloudStack Template Preparation"
Write-Info "=========================================="
Write-Host ""

# Function to safely execute commands with error handling
function Invoke-SafeCommand {
    param(
        [scriptblock]$Command,
        [string]$SuccessMessage,
        [string]$ErrorMessage
    )
    
    try {
        & $Command
        if ($?) {
            Write-Success "✓ $SuccessMessage"
        } else {
            Write-Warning "⚠ $ErrorMessage"
        }
    } catch {
        Write-Warning "⚠ $ErrorMessage - $($_.Exception.Message)"
    }
}

# SECTION 1: OPTIMIZATION
if (-not $SkipOptimization) {
    Write-Info "`n[1/3] Starting Windows Optimization..."
    Write-Info "========================================"
    
    # 1.1 Enable RDP
    Invoke-SafeCommand -Command {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0 -Force
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    } -SuccessMessage "RDP enabled" -ErrorMessage "Failed to enable RDP"
    
    # 1.2 Configure Power Settings
    Invoke-SafeCommand -Command {
        # Set to High Performance
        $powerPlan = Get-CimInstance -Name root\cimv2\power -Class win32_PowerPlan | Where-Object { $_.ElementName -eq "High performance" }
        if ($powerPlan) {
            powercfg /setactive $($powerPlan.InstanceID.ToString().Split("\")[1].Split("}")[0])
        } else {
            # If High Performance doesn't exist, use Balanced and set to maximum
            powercfg -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
            powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
        }
        
        # Set all timeouts to never
        powercfg -change -monitor-timeout-ac 0
        powercfg -change -monitor-timeout-dc 0
        powercfg -change -disk-timeout-ac 0
        powercfg -change -disk-timeout-dc 0
        powercfg -change -standby-timeout-ac 0
        powercfg -change -standby-timeout-dc 0
        powercfg -change -hibernate-timeout-ac 0
        powercfg -change -hibernate-timeout-dc 0
        
        # Disable hibernation
        powercfg -h off
    } -SuccessMessage "Power settings optimized" -ErrorMessage "Failed to optimize power settings"
    
    # 1.3 Set Time Zone to UTC
    Invoke-SafeCommand -Command {
        Set-TimeZone -Id "UTC" -ErrorAction Stop
    } -SuccessMessage "Time zone set to UTC" -ErrorMessage "Failed to set time zone"
    
    # 1.4 Enable ICMP (Ping)
    Invoke-SafeCommand -Command {
        # Remove existing rules first to avoid duplicates
        Remove-NetFirewallRule -DisplayName "Allow ICMPv4-In" -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName "Allow ICMPv6-In" -ErrorAction SilentlyContinue
        
        # Add new rules
        New-NetFirewallRule -DisplayName "Allow ICMPv4-In" -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -Profile Any -ErrorAction Stop | Out-Null
        New-NetFirewallRule -DisplayName "Allow ICMPv6-In" -Direction Inbound -Protocol ICMPv6 -IcmpType 8 -Action Allow -Profile Any -ErrorAction Stop | Out-Null
    } -SuccessMessage "ICMP (ping) enabled" -ErrorMessage "Failed to enable ICMP"
    
    # 1.5 Configure Page File (Fixed method for all Windows versions)
    Write-Info "Configuring page file..."
    try {
        # Disable automatic page file management
        $cs = Get-CimInstance Win32_ComputerSystem
        $cs | Set-CimInstance -Property @{AutomaticManagedPagefile = $false}
        
        # Remove existing page files
        $pagefiles = Get-CimInstance Win32_PageFileUsage
        foreach ($pagefile in $pagefiles) {
            $pagefile | Remove-CimInstance -ErrorAction SilentlyContinue
        }
        
        # Set new page file using WMI (more reliable across Windows versions)
        $PageFile = Get-WmiObject -Query "Select * From Win32_PageFileSetting Where Name='C:\\pagefile.sys'" -EnableAllPrivileges
        if ($null -ne $PageFile) {
            $PageFile.Delete()
        }
        
        # Create new page file
        $PageFileSettings = Get-WmiObject -Class Win32_PageFileSetting -EnableAllPrivileges
        if ($null -eq $PageFileSettings) {
            Set-WmiInstance -Class Win32_PageFileSetting -Arguments @{Name="C:\pagefile.sys"; InitialSize=4096; MaximumSize=4096} -EnableAllPrivileges | Out-Null
        }
        
        Write-Success "✓ Page file set to fixed 4GB"
    } catch {
        # Fallback method using registry
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "C:\pagefile.sys 4096 4096" -Type MultiString -Force
            Write-Success "✓ Page file configured via registry (will apply after reboot)"
        } catch {
            Write-Warning "⚠ Could not configure page file - $($_.Exception.Message)"
        }
    }
    
    # 1.6 Disable Services
    if ($DisableWindowsUpdate) {
        Invoke-SafeCommand -Command {
            Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
            Set-Service -Name wuauserv -StartupType Disabled -ErrorAction Stop
        } -SuccessMessage "Windows Update disabled" -ErrorMessage "Failed to disable Windows Update"
    }
    
    # Disable unnecessary services
    $servicesToDisable = @(
        @{Name="DiagTrack"; Description="Connected User Experiences and Telemetry"},
        @{Name="dmwappushservice"; Description="WAP Push Message Service"},
        @{Name="MapsBroker"; Description="Downloaded Maps Manager"},
        @{Name="XblAuthManager"; Description="Xbox Live Auth Manager"},
        @{Name="XblGameSave"; Description="Xbox Live Game Save"},
        @{Name="XboxNetApiSvc"; Description="Xbox Live Networking Service"}
    )
    
    foreach ($service in $servicesToDisable) {
        Invoke-SafeCommand -Command {
            $svc = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
            if ($svc) {
                Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
                Set-Service -Name $service.Name -StartupType Disabled -ErrorAction SilentlyContinue
            }
        } -SuccessMessage "Disabled $($service.Description)" -ErrorMessage "Failed to disable $($service.Description)"
    }
    
    # 1.7 Configure Explorer Settings
    Invoke-SafeCommand -Command {
        # Show file extensions
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Force
        # Show hidden files
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1 -Force
        # Show system files
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Value 1 -Force
    } -SuccessMessage "Explorer settings configured" -ErrorMessage "Failed to configure Explorer settings"
    
    # 1.8 Network Configuration
    Invoke-SafeCommand -Command {
        # Ensure all network profiles are set to Private (for better discovery)
        Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue
        
        # Enable Network Discovery
        netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes 2>$null
        
        # Ensure DHCP is enabled on all adapters
        Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | ForEach-Object {
            Set-NetIPInterface -InterfaceAlias $_.Name -Dhcp Enabled -ErrorAction SilentlyContinue
        }
    } -SuccessMessage "Network configured for cloud" -ErrorMessage "Failed to configure network"
    
    # 1.9 Windows Defender (if requested)
    if ($DisableDefender) {
        Invoke-SafeCommand -Command {
            # Disable Windows Defender via Registry
            $defenderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
            if (-not (Test-Path $defenderPath)) {
                New-Item -Path $defenderPath -Force | Out-Null
            }
            Set-ItemProperty -Path $defenderPath -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force
            
            # Disable real-time protection
            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        } -SuccessMessage "Windows Defender disabled" -ErrorMessage "Failed to disable Windows Defender"
    }
    
    # 1.10 Additional Registry Optimizations
    Invoke-SafeCommand -Command {
        # Disable Cortana
        $cortanaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        if (-not (Test-Path $cortanaPath)) {
            New-Item -Path $cortanaPath -Force | Out-Null
        }
        Set-ItemProperty -Path $cortanaPath -Name "AllowCortana" -Value 0 -Type DWord -Force
        
        # Disable Telemetry
        $telemetryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        if (-not (Test-Path $telemetryPath)) {
            New-Item -Path $telemetryPath -Force | Out-Null
        }
        Set-ItemProperty -Path $telemetryPath -Name "AllowTelemetry" -Value 0 -Type DWord -Force
        
        # Disable Consumer Features
        $cloudPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        if (-not (Test-Path $cloudPath)) {
            New-Item -Path $cloudPath -Force | Out-Null
        }
        Set-ItemProperty -Path $cloudPath -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Force
    } -SuccessMessage "Registry optimizations applied" -ErrorMessage "Failed to apply registry optimizations"
}

# SECTION 2: CLEANUP
if (-not $SkipCleanup) {
    Write-Info "`n[2/3] Starting System Cleanup..."
    Write-Info "========================================"
    
    # 2.1 Stop Windows Update Service
    Write-Info "Stopping Windows Update service..."
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Stop-Service -Name bits -Force -ErrorAction SilentlyContinue
    
    # 2.2 Clean Windows Update Files
    Invoke-SafeCommand -Command {
        Remove-Item -Path "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\Windows\SoftwareDistribution\DataStore\*" -Recurse -Force -ErrorAction SilentlyContinue
    } -SuccessMessage "Windows Update cache cleared" -ErrorMessage "Failed to clear Windows Update cache"
    
    # 2.3 Clean Temporary Files
    Write-Info "Cleaning temporary files..."
    $tempPaths = @(
        $env:TEMP,
        "C:\Windows\Temp",
        "C:\Windows\Prefetch",
        "$env:LOCALAPPDATA\Temp"
    )
    
    foreach ($path in $tempPaths) {
        if (Test-Path $path) {
            Invoke-SafeCommand -Command {
                Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | 
                    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            } -SuccessMessage "Cleaned: $path" -ErrorMessage "Partial cleanup: $path"
        }
    }
    
    # 2.4 Clear Event Logs
    Write-Info "Clearing event logs..."
    try {
        wevtutil el | ForEach-Object {
            wevtutil cl $_ 2>$null
        }
        Write-Success "✓ Event logs cleared"
    } catch {
        Write-Warning "⚠ Some event logs could not be cleared"
    }
    
    # 2.5 Clean Thumbnail Cache
    Invoke-SafeCommand -Command {
        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue
    } -SuccessMessage "Thumbnail cache cleared" -ErrorMessage "Failed to clear thumbnail cache"
    
    # 2.6 Run Disk Cleanup
    Write-Info "Configuring disk cleanup..."
    try {
        # Set cleanup options
        $cleanupKeys = @(
            "Active Setup Temp Folders",
            "BranchCache",
            "Downloaded Program Files",
            "Internet Cache Files",
            "Memory Dump Files",
            "Old ChkDsk Files",
            "Previous Installations",
            "Recycle Bin",
            "Service Pack Cleanup",
            "Setup Log Files",
            "System error memory dump files",
            "System error minidump files",
            "Temporary Files",
            "Temporary Setup Files",
            "Thumbnail Cache",
            "Update Cleanup",
            "Upgrade Discarded Files",
            "User file versions",
            "Windows Defender",
            "Windows ESD installation files",
            "Windows Error Reporting Archive Files",
            "Windows Error Reporting Queue Files",
            "Windows Error Reporting System Archive Files",
            "Windows Error Reporting System Queue Files",
            "Windows Upgrade Log Files"
        )
        
        # Create registry entries for disk cleanup
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
        foreach ($key in $cleanupKeys) {
            $keyPath = Join-Path $regPath $key
            if (Test-Path $keyPath) {
                Set-ItemProperty -Path $keyPath -Name "StateFlags0100" -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Run cleanup
        Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:100" -NoNewWindow -Wait -ErrorAction SilentlyContinue
        Write-Success "✓ Disk cleanup completed"
    } catch {
        Write-Warning "⚠ Disk cleanup encountered issues but continued"
    }
    
    # 2.7 DISM Cleanup
    Write-Info "Running DISM cleanup (this may take several minutes)..."
    try {
        # Component store cleanup
        DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase /Quiet
        Write-Success "✓ DISM cleanup completed"
    } catch {
        Write-Warning "⚠ DISM cleanup encountered issues but continued"
    }
    
    # 2.8 Clear DNS Cache
    Invoke-SafeCommand -Command {
        Clear-DnsClientCache
        ipconfig /flushdns
    } -SuccessMessage "DNS cache cleared" -ErrorMessage "Failed to clear DNS cache"
    
    # 2.9 Reset Windows Search
    Invoke-SafeCommand -Command {
        Stop-Service -Name WSearch -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\*" -Recurse -Force -ErrorAction SilentlyContinue
    } -SuccessMessage "Windows Search index reset" -ErrorMessage "Failed to reset Windows Search"
    
    # 2.10 Remove Windows Bloatware (if requested)
    if ($RemoveBloatware) {
        Write-Info "Removing Windows bloatware apps..."
        $bloatwareApps = @(
            "Microsoft.BingWeather",
            "Microsoft.GetHelp",
            "Microsoft.Getstarted",
            "Microsoft.Microsoft3DViewer",
            "Microsoft.MicrosoftOfficeHub",
            "Microsoft.MicrosoftSolitaireCollection",
            "Microsoft.MixedReality.Portal",
            "Microsoft.People",
            "Microsoft.Print3D",
            "Microsoft.SkypeApp",
            "Microsoft.Wallet",
            "Microsoft.WindowsAlarms",
            "Microsoft.WindowsFeedbackHub",
            "Microsoft.WindowsMaps",
            "Microsoft.Xbox.TCUI",
            "Microsoft.XboxApp",
            "Microsoft.XboxGameOverlay",
            "Microsoft.XboxGamingOverlay",
            "Microsoft.XboxIdentityProvider",
            "Microsoft.XboxSpeechToTextOverlay",
            "Microsoft.YourPhone",
            "Microsoft.ZuneMusic",
            "Microsoft.ZuneVideo"
        )
        
        foreach ($app in $bloatwareApps) {
            Invoke-SafeCommand -Command {
                Get-AppxPackage -Name $app -AllUsers -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction Stop
                Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | 
                    Where-Object DisplayName -like $app | 
                    Remove-AppxProvisionedPackage -Online -ErrorAction Stop
            } -SuccessMessage "Removed: $app" -ErrorMessage "Could not remove: $app"
        }
    }
}

# SECTION 3: SYSPREP PREPARATION
if (-not $SkipSysprep) {
    Write-Info "`n[3/3] Preparing for Sysprep..."
    Write-Info "========================================"
    
    # 3.1 Create Sysprep Unattend File
    Write-Info "Creating sysprep unattend.xml..."
    $unattendXml = @'
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="generalize">
        <component name="Microsoft-Windows-Security-SPP" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <SkipRearm>1</SkipRearm>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <InputLocale>en-US</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UserLocale>en-US</UserLocale>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideLocalAccountScreen>true</HideLocalAccountScreen>
                <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <NetworkLocation>Work</NetworkLocation>
                <ProtectYourPC>1</ProtectYourPC>
                <SkipMachineOOBE>true</SkipMachineOOBE>
                <SkipUserOOBE>true</SkipUserOOBE>
            </OOBE>
            <TimeZone>UTC</TimeZone>
        </component>
    </settings>
</unattend>
'@
    
    try {
        $unattendPath = "C:\Windows\System32\Sysprep\unattend.xml"
        $unattendXml | Out-File -FilePath $unattendPath -Encoding UTF8 -Force
        Write-Success "✓ Sysprep unattend.xml created"
    } catch {
        Write-Error "Failed to create unattend.xml: $($_.Exception.Message)"
    }
    
    # 3.2 Verify VirtIO Drivers
    Write-Info "Verifying VirtIO drivers..."
    $virtioDrivers = Get-WmiObject Win32_PnPSignedDriver | Where-Object {$_.DriverProvider -like "*Red Hat*"}
    if ($virtioDrivers) {
        Write-Success "✓ Found $($virtioDrivers.Count) VirtIO drivers installed"
        $virtioDrivers | ForEach-Object {
            Write-Host "  - $($_.DeviceName) (Version: $($_.DriverVersion))" -ForegroundColor Gray
        }
    } else {
        Write-Warning "⚠ No VirtIO drivers found! Template may not work properly."
    }
    
    # 3.3 Final Checks
    Write-Info "`nPerforming final checks..."
    
    # Check network is DHCP
    $dhcpEnabled = Get-NetIPConfiguration | Where-Object {$_.Dhcp -eq "Enabled"}
    if ($dhcpEnabled) {
        Write-Success "✓ Network is configured for DHCP"
    } else {
        Write-Warning "⚠ Network may not be configured for DHCP"
    }
    
    # Check Administrator account
    $adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    if ($adminAccount -and $adminAccount.Enabled) {
        Write-Success "✓ Administrator account is enabled"
    } else {
        Write-Warning "⚠ Administrator account may be disabled"
    }
    
    # 3.4 Create Sysprep Script
    Write-Info "Creating sysprep execution script..."
    $sysprepScript = @'
@echo off
echo ==========================================
echo CloudStack Windows Template Sysprep
echo ==========================================
echo.
echo This will generalize Windows and shut down the VM.
echo After shutdown, DO NOT boot the VM again!
echo Create the template immediately in CloudStack.
echo.
echo Press Ctrl+C to cancel, or
pause

cd /d C:\Windows\System32\Sysprep
echo.
echo Running Sysprep...
sysprep.exe /generalize /oobe /shutdown /unattend:unattend.xml

if errorlevel 1 (
    echo.
    echo ERROR: Sysprep failed!
    echo Check C:\Windows\System32\Sysprep\Panther\setupact.log
    pause
)
'@
    
    try {
        $sysprepScript | Out-File -FilePath "C:\RunSysprep.bat" -Encoding ASCII -Force
        Write-Success "✓ Sysprep script created at C:\RunSysprep.bat"
    } catch {
        Write-Error "Failed to create sysprep script: $($_.Exception.Message)"
    }
}

# COMPLETION
Write-Info "`n=========================================="
Write-Success "Template Preparation Complete!"
Write-Info "=========================================="

# Summary
Write-Host "`nSummary of actions performed:" -ForegroundColor Cyan
if (-not $SkipOptimization) {
    Write-Host "  ✓ Windows optimized for cloud deployment" -ForegroundColor Green
}
if (-not $SkipCleanup) {
    Write-Host "  ✓ System cleaned and temporary files removed" -ForegroundColor Green
}
if (-not $SkipSysprep) {
    Write-Host "  ✓ Sysprep files prepared" -ForegroundColor Green
}

# Next Steps
Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "1. Review any warnings above" -ForegroundColor White
Write-Host "2. Run C:\RunSysprep.bat to generalize Windows" -ForegroundColor White
Write-Host "3. After VM shuts down, create template in CloudStack immediately" -ForegroundColor White
Write-Host "4. DO NOT boot this VM again after sysprep!" -ForegroundColor Red

Write-Host "`nIMPORTANT CloudStack Template Settings:" -ForegroundColor Yellow
Write-Host "  - Password Enabled: YES" -ForegroundColor Cyan
Write-Host "  - OS Type: Select correct Windows version" -ForegroundColor Cyan
Write-Host "  - Root Disk Controller: VirtIO" -ForegroundColor Cyan

Write-Host "`nPress any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
