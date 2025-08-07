# Windows Cleanup Commands Before Creating Template
# Run in PowerShell as Administrator

Write-Host "Starting Windows Cleanup..." -ForegroundColor Yellow

# 1. Clean Windows Update files
Stop-Service -Name wuauserv -Force
Remove-Item -Path "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
Start-Service -Name wuauserv
Write-Host "✓ Windows Update cache cleared" -ForegroundColor Green

# 2. Clean temporary files
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Prefetch\*" -Force -ErrorAction SilentlyContinue
Write-Host "✓ Temporary files cleaned" -ForegroundColor Green

# 3. Run Disk Cleanup
Write-Host "Running disk cleanup (this may take a few minutes)..." -ForegroundColor Yellow
cleanmgr /sagerun:99 2>$null

# 4. Clear event logs
Write-Host "Clearing event logs..." -ForegroundColor Yellow
wevtutil el | ForEach-Object {
    wevtutil cl $_
}
Write-Host "✓ Event logs cleared" -ForegroundColor Green

# 5. Reset Windows Search
Stop-Service -Name WSearch -Force
Remove-Item -Path "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\*" -Recurse -Force -ErrorAction SilentlyContinue
Start-Service -Name WSearch
Write-Host "✓ Windows Search reset" -ForegroundColor Green

# 6. Clear thumbnail cache
Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue
Write-Host "✓ Thumbnail cache cleared" -ForegroundColor Green

# 7. Compact OS (optional - saves space but takes time)
# Compact.exe /CompactOS:always

# 8. Run DISM cleanup
Write-Host "Running DISM cleanup..." -ForegroundColor Yellow
DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase

Write-Host "`n✅ Cleanup complete!" -ForegroundColor Green
Write-Host "Next step: Run Sysprep" -ForegroundColor Cyan
