foreach ($s in @("1", "2", "3")) {
    Write-Host ""
    Write-Host "======== verify-chain CertSet $s ========" -ForegroundColor Cyan
    & "$PSScriptRoot\verify-chain.ps1" -CertSet $s
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
