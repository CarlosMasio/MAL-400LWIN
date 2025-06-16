# ─────────────────────────────────────────────────────────────
# Mal-Protocol Windows Monitor - Final Working Version
# ─────────────────────────────────────────────────────────────

# SET CONFIG HERE
$PythonPath = "python"  # Or full path to python.exe
$MalProtocolPath = "C:\MalProtocol-Windows\malprotocol.py"
$WatchFolder = "$env:USERPROFILE\Downloads"

# CREATE WATCHER FIRST
$fsw = New-Object System.IO.FileSystemWatcher
$fsw.Path = $WatchFolder
$fsw.Filter = "*.*"
$fsw.IncludeSubdirectories = $false
$fsw.EnableRaisingEvents = $true

# Show banner
Write-Host ""
Write-Host "🧠 [Mal-Protocol Monitor] Watching: $WatchFolder" -ForegroundColor Cyan
Write-Host "🔄 Will auto-scan any new file using malprotocol.py" -ForegroundColor Yellow
Write-Host "📌 Leave this terminal running..." -ForegroundColor Green
Write-Host "────────────────────────────────────────────────────"

# Save config for use inside event block
$global:__PythonPath = $PythonPath
$global:__MalProtocolPath = $MalProtocolPath

# Register event handler
Register-ObjectEvent -InputObject $fsw -EventName Created -Action {
    param($sender, $eventArgs)

    Start-Sleep -Milliseconds 1500
    $filePath = $eventArgs.FullPath

    if (Test-Path $filePath) {
        $fileName = [System.IO.Path]::GetFileName($filePath)
        Write-Host "`n[+] Detected new file: $fileName" -ForegroundColor Cyan

        $args = @($global:__MalProtocolPath, $filePath, '--no-vt')
        Start-Process -FilePath $global:__PythonPath -ArgumentList $args -WindowStyle Hidden
    }
}

# Keep script alive
while ($true) {
    Start-Sleep -Seconds 5
}
