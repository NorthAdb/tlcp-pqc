$env:TLCP_ROOT = "D:\20240429certificate-verification\tlcp-pqc"
$TLCP_ROOT = $env:TLCP_ROOT

$env:PATH = "$TLCP_ROOT\bin;$TLCP_ROOT\lib;$env:PATH"
$env:OPENSSL_CONF = "$TLCP_ROOT\config\openssl-all-providers.cnf"
$env:OPENSSL_MODULES = "$TLCP_ROOT\providers"

$env:PQMAGIC_PROVIDER = "$TLCP_ROOT\providers\pqmagic.dll"
$env:ML_DSA_SM2_PROVIDER = "$TLCP_ROOT\providers\libml_dsa_sm2_provider.dll"
$env:PQMAGIC_STD_LIB = "$TLCP_ROOT\providers\pqmagic.dll"
$env:CERT_VERIFY_SO = "$TLCP_ROOT\providers\cert_verify.dll"
$env:AIGIS_PROVIDER = "$TLCP_ROOT\providers\aigis.dll"
$env:CERT_VERIFY_VERIFY_INFO = "1"

$env:OPENSSL = "$TLCP_ROOT\bin\openssl.exe"

Write-Host "TLCP environment loaded: $TLCP_ROOT" -ForegroundColor Green
