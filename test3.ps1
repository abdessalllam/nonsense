@echo off
REM Sysprep script for CloudStack Windows Template
REM Save this as C:\sysprep-cloudstack.bat and run as Administrator

echo ========================================
echo CloudStack Windows Template Sysprep
echo ========================================
echo.
echo This will generalize Windows and shut down the VM.
echo After shutdown, DO NOT boot the VM again!
echo.
pause

REM Create unattend.xml for CloudStack
echo Creating unattend.xml...
(
echo ^<?xml version="1.0" encoding="utf-8"?^>
echo ^<unattend xmlns="urn:schemas-microsoft-com:unattend"^>
echo     ^<settings pass="generalize"^>
echo         ^<component name="Microsoft-Windows-Security-SPP" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"^>
echo             ^<SkipRearm^>1^</SkipRearm^>
echo         ^</component^>
echo     ^</settings^>
echo     ^<settings pass="oobeSystem"^>
echo         ^<component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"^>
echo             ^<OOBE^>
echo                 ^<HideEULAPage^>true^</HideEULAPage^>
echo                 ^<HideLocalAccountScreen^>true^</HideLocalAccountScreen^>
echo                 ^<HideOEMRegistrationScreen^>true^</HideOEMRegistrationScreen^>
echo                 ^<HideOnlineAccountScreens^>true^</HideOnlineAccountScreens^>
echo                 ^<HideWirelessSetupInOOBE^>true^</HideWirelessSetupInOOBE^>
echo                 ^<ProtectYourPC^>1^</ProtectYourPC^>
echo                 ^<SkipMachineOOBE^>true^</SkipMachineOOBE^>
echo                 ^<SkipUserOOBE^>true^</SkipUserOOBE^>
echo             ^</OOBE^>
echo             ^<TimeZone^>UTC^</TimeZone^>
echo         ^</component^>
echo     ^</settings^>
echo ^</unattend^>
) > C:\Windows\System32\Sysprep\unattend.xml

echo.
echo Running Sysprep...
cd /d C:\Windows\System32\Sysprep
sysprep.exe /generalize /oobe /shutdown /unattend:unattend.xml

REM Script ends here - sysprep will shutdown the VM
