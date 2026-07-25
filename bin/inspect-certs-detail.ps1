$TLCP_ROOT = "D:\20240429certificate-verification\tlcp-pqc"
$env:PATH = "$TLCP_ROOT\bin;$TLCP_ROOT\lib;$TLCP_ROOT\tongsuo-install\bin;$TLCP_ROOT\tongsuo-install\lib;$env:PATH"
$env:OPENSSL_CONF = "$TLCP_ROOT\config\openssl-all-providers.cnf"
$env:OPENSSL_MODULES = "$TLCP_ROOT\providers"
$openssl = "$TLCP_ROOT\bin\openssl.exe"
$prov = @(
    "-provider-path", "$TLCP_ROOT\providers",
    "-provider", "default", "-provider", "pqmagic",
    "-provider", "ml_dsa_sm2", "-provider", "cert_verify", "-provider", "aigis_enc"
)

foreach ($set in @("2", "3")) {
    Write-Host "`n==================== certs/$set 详细公钥与签名 ====================" -ForegroundColor Cyan
    foreach ($name in @("root", "yunying", "user_sig", "user_enc")) {
        $f = "$TLCP_ROOT\certs\$set\$name.crt"
        Write-Host "`n--- $name.crt ---" -ForegroundColor Yellow
        & $openssl x509 -in $f -noout -text @prov 2>&1 | Select-String -Pattern "Signature Algorithm|Public Key Algorithm|Public-Key:|Subject Public Key Info|ML-DSA|ML-KEM|SM2|hybrid|Composite|Issuer:|Subject:" -Context 0,2
    }
}
