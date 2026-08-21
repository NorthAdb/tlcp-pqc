param(
    [ValidateSet("mlkemdsa","aigis","all")]
    [string]$Algo = "all"
)

$algos = if ($Algo -eq "all") { @("mlkemdsa", "aigis") } else { @($Algo) }

foreach ($a in $algos) {
    foreach ($s in @("pure", "concat", "ext")) {
        Write-Host ""
        Write-Host "======== verify-chain Algo=$a CertSet=$s ========" -ForegroundColor Cyan
        & "$PSScriptRoot\verify-chain.ps1" -Algo $a -CertSet $s
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
}
