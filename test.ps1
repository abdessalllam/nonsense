# Windows CloudStack VM Optimization Commands
# Run these in PowerShell as Administrator

# 1. Enable RDP (if not already enabled)
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Write-Host "✓ RDP Enabled" -ForegroundColor Green

# 2. Set Power Settings
powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  # High Performance
powercfg -change -monitor-timeout-ac 0
powercfg -change -disk-timeout-ac 0
powercfg -change -standby-timeout-ac 0
powercfg -h off  # Disable hibernation
Write-Host "✓ Power settings optimized" -ForegroundColor Green

# 3. Set Time Zone to UTC (recommended for cloud)
Set-TimeZone -Id "UTC"
Write-Host "✓ Time zone set to UTC" -ForegroundColor Green

# 4. Enable ICMP (Ping)
New-NetFirewallRule -DisplayName "Allow ICMPv4-In" -Protocol ICMPv4 -IcmpType 8 -Enabled True -Profile Any -Action Allow -ErrorAction SilentlyContinue
Write-Host "✓ ICMP enabled" -ForegroundColor Green

# 5. Configure Windows Update (optional - disable for templates)
# Set-Service -Name wuauserv -StartupType Disabled
# Stop-Service -Name wuauserv

# 6. Set fixed pagefile (4GB)
$ComputerSystem = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges
$ComputerSystem.AutomaticManagedPagefile = $false
$ComputerSystem.Put()

$PageFile = Get-WmiObject Win32_PageFileSetting
if ($PageFile) { $PageFile.Delete() }

Set-WmiInstance -Class Win32_PageFileSetting -Arguments @{
    Name = "C:\pagefile.sys"
    InitialSize = 4096
    MaximumSize = 4096
}
Write-Host "✓ Pagefile set to fixed 4GB" -ForegroundColor Green

# 7. Disable unnecessary services
$ServicesToDisable = @(
    "DiagTrack",          # Telemetry
    "dmwappushservice",   # WAP Push
    "XblAuthManager",     # Xbox
    "XblGameSave",        # Xbox
    "XboxNetApiSvc"       # Xbox
)

foreach ($service in $ServicesToDisable) {
    try {
        Stop-Service -Name $service -ErrorAction SilentlyContinue
        Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host "✓ Disabled: $service" -ForegroundColor Green
    } catch {}
}

# 8. Show file extensions and hidden files
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1
Write-Host "✓ Explorer settings configured" -ForegroundColor Green

Write-Host "`n✅ Optimization complete!" -ForegroundColor Green
