param(
    [Parameter(Mandatory=$true)]
    [string]$CertPath,

    [switch]$Summary
)

. "$PSScriptRoot\Set-TlcpEnv.ps1"

$prov = @(
    "-provider-path", "$env:TLCP_ROOT\lib",
    "-provider", "default",
    "-provider", $env:PQMAGIC_PROVIDER,
    "-provider", $env:ML_DSA_SM2_PROVIDER
)

if ($Summary) {
    & $env:OPENSSL x509 -in $CertPath -noout -subject -issuer -dates -serial @prov
    & $env:OPENSSL x509 -in $CertPath -noout -signature_algorithm @prov
} else {
    & $env:OPENSSL x509 -in $CertPath -text -noout @prov
}
