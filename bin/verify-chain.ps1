param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("pure","concat","ext")]
    [string]$CertSet,

    [ValidateSet("mlkemdsa","aigis")]
    [string]$Algo = "mlkemdsa",

    [ValidateSet("yunying","user_sig","user_enc","all")]
    [string]$Leaf = "all",

    # root：以根证为信任锚验整条链；yunying：以中间 CA 为信任锚验 user_*（-partial_chain）
    [ValidateSet("root","yunying")]
    [string]$TrustAnchor = "root"
)

. "$PSScriptRoot\Set-TlcpEnv.ps1"

$CertSetDirs = @{
    "mlkemdsa|pure"   = "Pure PQC Certificate\mlkemdsa"
    "mlkemdsa|concat" = "Hybrid Concatenated Certificate\mlkemdsa"
    "mlkemdsa|ext"    = "Hybrid Using Extensions Certificate\mlkemdsa"
    "aigis|pure"      = "Pure PQC Certificate\aigis"
    "aigis|concat"    = "Hybrid Concatenated Certificate\aigissm2"
    "aigis|ext"       = "Hybrid Using Extensions Certificate\sm2extaigis"
}

$key = "$Algo|$CertSet"
if (-not $CertSetDirs.ContainsKey($key)) {
    Write-Error "未知组合: Algo=$Algo CertSet=$CertSet"
    exit 1
}

$base = Join-Path $env:TLCP_ROOT ("certs\" + $CertSetDirs[$key])
$root = Join-Path $base "root.crt"
$yunying = Join-Path $base "yunying.crt"

if (-not (Test-Path -LiteralPath $root)) {
    Write-Error "找不到证书目录: $base"
    exit 1
}

$leaves = if ($Leaf -eq "all") {
    if ($TrustAnchor -eq "yunying") {
        @("user_sig", "user_enc")
    } else {
        @("yunying", "user_sig", "user_enc")
    }
} else {
    @($Leaf)
}

Write-Host "======== $Algo / $CertSet ($($CertSetDirs[$key])) 证书链验证 (TrustAnchor=$TrustAnchor) ========" -ForegroundColor Cyan

foreach ($name in $leaves) {
    $cert = Join-Path $base "$name.crt"
    if (-not (Test-Path -LiteralPath $cert)) {
        Write-Host "SKIP: 找不到 ${name}.crt" -ForegroundColor DarkYellow
        continue
    }
    Write-Host ""
    Write-Host ">>> 验证 ${name}.crt" -ForegroundColor Yellow
    if ($TrustAnchor -eq "yunying") {
        if ($name -eq "yunying") {
            Write-Host "SKIP: 以 yunying 为信任锚时请验 user_sig / user_enc" -ForegroundColor DarkYellow
            continue
        }
        & $env:OPENSSL verify -CAfile $yunying -partial_chain $cert
    } else {
        & $env:OPENSSL verify -CAfile $root -untrusted $yunying $cert
    }
}
