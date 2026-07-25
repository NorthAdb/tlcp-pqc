$TLCP_ROOT = "D:\20240429certificate-verification\tlcp-pqc"
$env:PATH = "$TLCP_ROOT\bin;$TLCP_ROOT\lib;$env:PATH"
$env:OPENSSL_CONF = "$TLCP_ROOT\config\openssl-all-providers.cnf"
$env:OPENSSL_MODULES = "$TLCP_ROOT\providers"
$openssl = "$TLCP_ROOT\bin\openssl.exe"
$prov = @("-provider-path", "$TLCP_ROOT\providers", "-provider", "default", "-provider", "pqmagic", "-provider", "ml_dsa_sm2")

function Get-CertField($path, $field) {
    $line = & $openssl x509 -in $path -noout -$field @prov 2>&1 | Out-String
    return ($line -replace "^${field}=", "").Trim()
}

Write-Host "=== chain issuer/subject match ===" -ForegroundColor Cyan
foreach ($set in @("1","2","3")) {
    $base = "$TLCP_ROOT\certs\$set"
    $rootSub = Get-CertField "$base\root.crt" "subject"
    $yunSub = Get-CertField "$base\yunying.crt" "subject"
    $yunIss = Get-CertField "$base\yunying.crt" "issuer"
    $sigIss = Get-CertField "$base\user_sig.crt" "issuer"
    $encIss = Get-CertField "$base\user_enc.crt" "issuer"

    $ok1 = ($yunIss -eq $rootSub)
    $ok2 = ($sigIss -eq $yunSub)
    $ok3 = ($encIss -eq $yunSub)
    $color = if ($ok1 -and $ok2 -and $ok3) { "Green" } else { "Red" }
    Write-Host ("certs/{0}: root<-yunying={1}, yunying<-user_sig={2}, yunying<-user_enc={3}" -f $set, $ok1, $ok2, $ok3) -ForegroundColor $color
}

Write-Host ""
Write-Host "=== notAfter (expiry) ===" -ForegroundColor Cyan
foreach ($set in @("1","2","3")) {
    foreach ($name in @("root","yunying","user_sig","user_enc")) {
        $f = "$TLCP_ROOT\certs\$set\$name.crt"
        $nb = Get-CertField $f "startdate"
        $na = Get-CertField $f "enddate"
        Write-Host ("  certs/{0}/{1}.crt : {2} -> {3}" -f $set, $name, $nb, $na)
    }
}
