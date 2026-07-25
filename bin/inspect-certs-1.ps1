$TLCP_ROOT = "D:\20240429certificate-verification\tlcp-pqc"
$env:PATH = "$TLCP_ROOT\bin;$TLCP_ROOT\lib;$TLCP_ROOT\tongsuo-install\bin;$TLCP_ROOT\tongsuo-install\lib;$env:PATH"
$env:OPENSSL_CONF = "$TLCP_ROOT\config\openssl-all-providers.cnf"
$env:OPENSSL_MODULES = "$TLCP_ROOT\providers"
$env:PQMAGIC_STD_LIB = "$TLCP_ROOT\providers\pqmagic.dll"
$env:CERT_VERIFY_SO = "$TLCP_ROOT\providers\cert_verify.dll"
$openssl = "$TLCP_ROOT\bin\openssl.exe"
$prov = @("-provider-path", "$TLCP_ROOT\providers", "-provider", "default", "-provider", "pqmagic", "-provider", "ml_dsa_sm2", "-provider", "cert_verify")

Write-Host "==================== certs/1 证书结构 ====================" -ForegroundColor Cyan
foreach ($name in @("root", "yunying", "user_sig", "user_enc")) {
    $f = "$TLCP_ROOT\certs\1\$name.crt"
    Write-Host "`n--- $name.crt ---" -ForegroundColor Yellow
    & $openssl x509 -in $f -noout -subject -issuer -dates @prov 2>&1
    & $openssl x509 -in $f -noout -text @prov 2>&1 | Select-String -Pattern "Signature Algorithm|Public Key Algorithm|Public-Key:|PQC-|ML-DSA|ML-KEM|SM2" | Select-Object -First 8
}
