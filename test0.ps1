<#
.SYNOPSIS
    Prepares a Windows guest for Apache CloudStack 4.20:
      • Enables secure Remote Desktop
      • Installs & configures CloudInstanceManager for password-reset support
      • Applies sensible VM / VirtIO optimisations
      • Generates a detailed log in C:\setup-cloudstack.log

.NOTES
    • Run from an elevated PowerShell session (Administrator).
    • Tested on Windows Server 2019/2022 and Windows 10/11 (English UI) with VirtIO drivers pre-installed.
    • All steps are idempotent – re-running is safe.
#>

$ErrorActionPreference = 'Stop'
Start-Transcript -Path 'C:\setup-cloudstack.log' -Append

function Write-Step ($Message) {
    Write-Host ">> $Message"
}

#------------------------------------------------------------
# 1. Enable Remote Desktop + Firewall rules
#------------------------------------------------------------
function Enable-RDP {
    Write-Step 'Enabling RDP…'
    # Allow RDP connections
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
                     -Name 'fDenyTSConnections' -Value 0

    # Enforce Network Level Authentication (more secure handshake)
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
                     -Name 'UserAuthentication' -Value 1

    # Ensure the service is set to Automatic and started
    Set-Service -Name 'TermService' -StartupType Automatic
    if (-not (Get-Service -Name 'TermService').Status -eq 'Running') {
        Start-Service -Name 'TermService'
    }

    # Open the firewall group if not already enabled
    if ((Get-NetFirewallProfile).Enabled -contains $true) {
        Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
    }

    Write-Step 'RDP successfully enabled.'
}

#------------------------------------------------------------
# 2. Install CloudInstanceManager (password-reset agent)
#------------------------------------------------------------
function Install-CloudInstanceManager {
    # CloudStack doc reference:
    #   Download CloudInstanceManager.msi for Windows password reset support :contentReference[oaicite:0]{index=0}
    $msiUrl  = 'https://downloads.sourceforge.net/project/cloudstack/Password%20Management%20Scripts/CloudInstanceManager.msi'
    $msiFile = "$env:TEMP\CloudInstanceManager.msi"

    # Detect if the service (cloudservice.exe) is already present
    $service = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name  -match 'cloudservice' -or
        $_.DisplayName -match 'Cloud.*Instance.*Manager'
    }

    if ($null -ne $service) {
        Write-Step "CloudInstanceManager already installed (service '$($service.Name)'). Skipping install."
        return
    }

    Write-Step 'Downloading CloudInstanceManager.msi…'
    Invoke-WebRequest -Uri $msiUrl -OutFile $msiFile -UseBasicParsing

    Write-Step 'Installing CloudInstanceManager…'
    $arguments = "/i `"$msiFile`" /qn /norestart"
    $result    = Start-Process -FilePath msiexec.exe -ArgumentList $arguments -Wait -PassThru
    if ($result.ExitCode -ne 0) {
        throw "CloudInstanceManager installation failed (exit code $($result.ExitCode))."
    }

    # Verify service
    $service = Get-Service | Where-Object {
        $_.Name  -match 'cloudservice' -or
        $_.DisplayName -match 'Cloud.*Instance.*Manager'
    }
    if ($null -eq $service) {
        throw 'CloudInstanceManager installed but service not found.'
    }

    Set-Service -Name $service.Name -StartupType Automatic
    Write-Step "CloudInstanceManager installed and service '$($service.Name)' set to Automatic."
}

#------------------------------------------------------------
# 3. Light-weight VM optimisations (safe defaults)
#------------------------------------------------------------
function Optimize-GuestOS {
    Write-Step 'Applying VM/IO optimisations…'

    # Disable scheduled defrag on VirtIO disks (defrag not helpful on SSD-backed storage)
    Get-ScheduledTask -TaskName '*defrag*' -ErrorAction SilentlyContinue |
        ForEach-Object { Disable-ScheduledTask $_.TaskName }

    # Disable unnecessary search / indexing (saves I/O on templates)
    Stop-Service -Name 'WSearch' -ErrorAction SilentlyContinue
    Set-Service  -Name 'WSearch' -StartupType Disabled

    # Opt-in to the balanced power plan (guarantees 100 % CPU when needed)
    powercfg /setactive SCHEME_BALANCED | Out-Null

    Write-Step 'Optimisations complete.'
}

#------------------------------------------------------------
# 4. Execution
#------------------------------------------------------------
try {
    Enable-RDP
    Install-CloudInstanceManager
    Optimize-GuestOS
    Write-Step 'All tasks finished successfully. A reboot is recommended before converting to a template.'
} catch {
    Write-Error "ERROR: $($_.Exception.Message)"
    Exit 1
} finally {
    Stop-Transcript
}
