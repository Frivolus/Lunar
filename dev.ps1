Set-Location $PSScriptRoot
git status --short
Write-Host "`n--- Etat ---" -ForegroundColor Cyan
Get-Content "docs\STATE.md" | Select-Object -First 12
