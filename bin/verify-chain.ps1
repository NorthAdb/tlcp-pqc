param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("1","2","3")]
    [string]$CertSet,

    [ValidateSet("yunying","user_sig","user_enc","all")]
    [string]$Leaf = "all",

  # root：以根证为信任锚验整条链；yunying：以中间 CA 为信任锚验 user_*（-partial_chain）
    [ValidateSet("root","yunying")]
    [string]$TrustAnchor = "root"
)

. "$PSScriptRoot\Set-TlcpEnv.ps1"

$base = "$env:TLCP_ROOT\certs\$CertSet"
$root = "$base\root.crt"
$yunying = "$base\yunying.crt"

$leaves = if ($Leaf -eq "all") {
    if ($TrustAnchor -eq "yunying") {
        @("user_sig", "user_enc")
    } else {
        @("yunying", "user_sig", "user_enc")
    }
} else {
    @($Leaf)
}

Write-Host "======== certs/$CertSet 证书链验证 (TrustAnchor=$TrustAnchor) ========" -ForegroundColor Cyan

foreach ($name in $leaves) {
    $cert = "$base\$name.crt"
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
