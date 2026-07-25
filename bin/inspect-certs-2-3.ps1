$TLCP_ROOT = "D:\20240429certificate-verification\tlcp-pqc"
$env:PATH = "$TLCP_ROOT\bin;$TLCP_ROOT\lib;$TLCP_ROOT\tongsuo-install\bin;$TLCP_ROOT\tongsuo-install\lib;$env:PATH"
$env:OPENSSL_CONF = "$TLCP_ROOT\config\openssl-all-providers.cnf"
$env:OPENSSL_MODULES = "$TLCP_ROOT\providers"
$env:PQMAGIC_PROVIDER = "$TLCP_ROOT\providers\pqmagic.dll"
$env:ML_DSA_SM2_PROVIDER = "$TLCP_ROOT\providers\libml_dsa_sm2_provider.dll"
$openssl = "$TLCP_ROOT\bin\openssl.exe"
$prov = @(
    "-provider-path", "$TLCP_ROOT\providers",
    "-provider", "default",
    "-provider", "pqmagic",
    "-provider", "ml_dsa_sm2",
    "-provider", "cert_verify",
    "-provider", "aigis_enc"
)

foreach ($set in @("2", "3")) {
    Write-Host ""
    Write-Host "==================== certs/$set ====================" -ForegroundColor Cyan
    foreach ($name in @("root", "yunying", "user_sig", "user_enc")) {
        $f = "$TLCP_ROOT\certs\$set\$name.crt"
        if (-not (Test-Path $f)) { continue }
        Write-Host ""
        Write-Host "--- $name.crt ---" -ForegroundColor Yellow
        & $openssl x509 -in $f -noout -subject -issuer -dates -serial @prov 2>&1
        & $openssl x509 -in $f -noout -signature_algorithm @prov 2>&1
        & $openssl x509 -in $f -noout -ext subjectKeyIdentifier,authorityKeyIdentifier,keyUsage,extendedKeyUsage @prov 2>&1
    }
}
