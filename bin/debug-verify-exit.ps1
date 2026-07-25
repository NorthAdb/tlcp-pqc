$TLCP_ROOT = "D:\20240429certificate-verification\tlcp-pqc"
$env:PATH = "$TLCP_ROOT\bin;$TLCP_ROOT\lib;$TLCP_ROOT\tongsuo-install\lib;$env:PATH"
$env:OPENSSL_CONF = "$TLCP_ROOT\config\openssl-all-providers.cnf"
$env:OPENSSL_MODULES = "$TLCP_ROOT\providers"
$env:PQMAGIC_STD_LIB = "$TLCP_ROOT\providers\pqmagic.dll"
$env:CERT_VERIFY_SO = "$TLCP_ROOT\providers\cert_verify.dll"
$env:CERT_VERIFY_VERIFY_INFO = "1"
$openssl = "$TLCP_ROOT\bin\openssl.exe"

$tests = @(
    @{
        Name = "certs/1 yunying"
        Args = @(
            "verify", "-CAfile", "$TLCP_ROOT\certs\1\root.crt",
            "$TLCP_ROOT\certs\1\yunying.crt"
        )
    },
    @{
        Name = "certs/2 user_enc"
        Args = @(
            "verify", "-CAfile", "$TLCP_ROOT\certs\2\root.crt",
            "-untrusted", "$TLCP_ROOT\certs\2\yunying.crt",
            "$TLCP_ROOT\certs\2\user_enc.crt"
        )
    },
    @{
        Name = "certs/3 user_sig"
        Args = @(
            "verify", "-CAfile", "$TLCP_ROOT\certs\3\root.crt",
            "-untrusted", "$TLCP_ROOT\certs\3\yunying.crt",
            "$TLCP_ROOT\certs\3\user_sig.crt"
        )
    }
)

foreach ($t in $tests) {
    Write-Host ""
    Write-Host "=== $($t.Name) ===" -ForegroundColor Cyan
    $outFile = [System.IO.Path]::GetTempFileName()
    $errFile = [System.IO.Path]::GetTempFileName()
    $p = Start-Process -FilePath $openssl -ArgumentList $t.Args `
        -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    $code = $p.ExitCode
    $hex = "0x{0:X8}" -f ($code -band 0xFFFFFFFF)
    Write-Host "ExitCode: $code ($hex)"
    $stdout = Get-Content $outFile -Raw -ErrorAction SilentlyContinue
    $stderr = Get-Content $errFile -Raw -ErrorAction SilentlyContinue
    if ($stdout) { Write-Host "--- stdout ---`n$stdout" }
    if ($stderr) { Write-Host "--- stderr ---`n$stderr" }
    if (-not $stdout -and -not $stderr) { Write-Host "(no output)" -ForegroundColor Yellow }
    Remove-Item $outFile, $errFile -Force -ErrorAction SilentlyContinue
}
