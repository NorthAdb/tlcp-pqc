param(
    [Parameter(Position = 0)]
    [string[]]$CsrPath,

    [ValidateSet("root", "yunying", "user_sig", "all")]
    [string]$Name = "all",

    [string]$CsrDir = "",

    [switch]$Quiet
)

. "$PSScriptRoot\Set-TlcpEnv.ps1"

$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) {
    $py = Get-Command python3 -ErrorAction SilentlyContinue
}
if (-not $py) {
    Write-Error "未找到 python / python3"
    exit 1
}

$script = Join-Path $PSScriptRoot "verify-csr-certs2.py"
$verifier = Join-Path $PSScriptRoot "mldsa_sign_sm3.exe"
$openssl = $env:OPENSSL

$argsList = @($script, "--verifier", $verifier, "--openssl", $openssl)
if ($Quiet) { $argsList += "-q" }

if ($CsrPath -and $CsrPath.Count -gt 0) {
    $argsList += $CsrPath
} else {
    if ($CsrDir) {
        $argsList += @("--csr-dir", $CsrDir)
    }
    if ($Name -ne "all") {
        $argsList += @("--names", $Name)
    }
}

& $py.Source @argsList
exit $LASTEXITCODE
