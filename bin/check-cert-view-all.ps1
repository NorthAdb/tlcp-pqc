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

$names = @("root", "yunying", "user_sig", "user_enc")
$results = @()

foreach ($set in @("1", "2", "3")) {
    foreach ($name in $names) {
        $f = "$TLCP_ROOT\certs\$set\$name.crt"
        $row = [ordered]@{
            Set = $set
            Cert = $name
            Exists = (Test-Path $f)
            ParseOK = $false
            Subject = ""
            SigAlg = ""
            PubKeyAlg = ""
            Errors = ""
        }
        if (-not $row.Exists) {
            $row.Errors = "file missing"
            $results += [pscustomobject]$row
            continue
        }

        $errFile = [System.IO.Path]::GetTempFileName()
        $text = & $openssl x509 -in $f -text -noout @prov 2>$errFile
        $err = Get-Content $errFile -Raw -ErrorAction SilentlyContinue
        Remove-Item $errFile -Force -ErrorAction SilentlyContinue

        if ($LASTEXITCODE -ne 0) {
            $row.Errors = $err
        } else {
            $row.ParseOK = $true
            $t = $text | Out-String
            if ($t -match "Subject:\s*(.+?)\r?\n") { $row.Subject = $Matches[1].Trim() }
            if ($t -match "Signature Algorithm:\s*(.+?)\r?\n") { $row.SigAlg = $Matches[1].Trim() }
            if ($t -match "Public Key Algorithm:\s*(.+?)\r?\n") { $row.PubKeyAlg = $Matches[1].Trim() }
            if ($t -match "PQC-Subject-Public-Key") {
                if ($t -match "Algorithm:\s*(ML-[^\r\n]+)") {
                    $row.PubKeyAlg = $row.PubKeyAlg + " + ext:" + $Matches[1].Trim()
                }
            }
        }
        $results += [pscustomobject]$row
    }
}

Write-Host ""
Write-Host "=== cert view check (x509 -text) ===" -ForegroundColor Cyan
$results | Format-Table Set, Cert, ParseOK, PubKeyAlg, SigAlg -Wrap

$bad = $results | Where-Object { -not $_.ParseOK }
if ($bad) {
    Write-Host "FAILED:" -ForegroundColor Red
    $bad | ForEach-Object { Write-Host ("  certs/{0}/{1}.crt : {2}" -f $_.Set, $_.Cert, $_.Errors) -ForegroundColor Red }
} else {
    Write-Host "All 12 certs parsed OK with openssl x509 -text." -ForegroundColor Green
}

Write-Host ""
Write-Host "=== ASN.1 check (asn1parse) ===" -ForegroundColor Cyan
$asnFail = 0
foreach ($set in @("1", "2", "3")) {
    foreach ($name in $names) {
        $f = "$TLCP_ROOT\certs\$set\$name.crt"
        & $openssl asn1parse -in $f 2>$null | Out-Null
        $ok = ($LASTEXITCODE -eq 0)
        if (-not $ok) { $asnFail++ }
        $status = if ($ok) { "OK" } else { "FAIL" }
        $color = if ($ok) { "Green" } else { "Red" }
        Write-Host ("  certs/{0}/{1}.crt : {2}" -f $set, $name, $status) -ForegroundColor $color
    }
}
if ($asnFail -eq 0) {
    Write-Host "All asn1parse OK." -ForegroundColor Green
}
