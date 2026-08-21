<#
.SYNOPSIS
  样例证总验收：解析 / ASN.1 / issuer-subject 链关系 / 有效期。
  密码学验链请用 verify-chain.ps1 / verify-chain-all.ps1；单证查看用 inspect-cert.ps1。

  -Algo mlkemdsa（默认）或 aigis：
    pure/concat/ext 分别映射到对应样证目录。
#>
param(
    [ValidateSet("mlkemdsa","aigis")]
    [string]$Algo = "mlkemdsa"
)

. "$PSScriptRoot\Set-TlcpEnv.ps1"

$openssl = $env:OPENSSL
$prov = @(
    "-provider-path", "$env:TLCP_ROOT\providers",
    "-provider", "default", "-provider", "pqmagic",
    "-provider", "ml_dsa_sm2", "-provider", "cert_verify",
    "-provider", "aigis"
)

$CertSets = if ($Algo -eq "aigis") {
    [ordered]@{
        pure   = "Pure PQC Certificate\aigis"
        concat = "Hybrid Concatenated Certificate\aigissm2"
        ext    = "Hybrid Using Extensions Certificate\sm2extaigis"
    }
} else {
    [ordered]@{
        pure   = "Pure PQC Certificate\mlkemdsa"
        concat = "Hybrid Concatenated Certificate\mlkemdsa"
        ext    = "Hybrid Using Extensions Certificate\mlkemdsa"
    }
}

$names = @("root", "yunying", "user_sig", "user_enc")
$results = @()

function Get-CertField([string]$path, [string]$field) {
    $line = & $openssl x509 -in $path -noout -$field @prov 2>&1 | Out-String
    return ($line -replace "^${field}=", "").Trim()
}

function Get-CertBase([string]$setKey) {
    return (Join-Path $env:TLCP_ROOT ("certs\" + $CertSets[$setKey]))
}

foreach ($set in $CertSets.Keys) {
    $base = Get-CertBase $set
    foreach ($name in $names) {
        $f = Join-Path $base "$name.crt"
        $row = [ordered]@{
            Set = $set
            Cert = $name
            Exists = (Test-Path -LiteralPath $f)
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
$viewFail = 0
if ($bad) {
    $viewFail = @($bad).Count
    Write-Host "FAILED:" -ForegroundColor Red
    $bad | ForEach-Object { Write-Host ("  {0}/{1}.crt : {2}" -f $_.Set, $_.Cert, $_.Errors) -ForegroundColor Red }
} else {
    Write-Host "All 12 certs parsed OK with openssl x509 -text." -ForegroundColor Green
}

Write-Host ""
Write-Host "=== ASN.1 check (asn1parse) ===" -ForegroundColor Cyan
$asnFail = 0
foreach ($set in $CertSets.Keys) {
    $base = Get-CertBase $set
    foreach ($name in $names) {
        $f = Join-Path $base "$name.crt"
        & $openssl asn1parse -in $f 2>$null | Out-Null
        $ok = ($LASTEXITCODE -eq 0)
        if (-not $ok) { $asnFail++ }
        $status = if ($ok) { "OK" } else { "FAIL" }
        $color = if ($ok) { "Green" } else { "Red" }
        Write-Host ("  {0}/{1}.crt : {2}" -f $set, $name, $status) -ForegroundColor $color
    }
}
if ($asnFail -eq 0) {
    Write-Host "All asn1parse OK." -ForegroundColor Green
}

Write-Host ""
Write-Host "=== chain issuer/subject match ===" -ForegroundColor Cyan
$metaFail = 0
foreach ($set in $CertSets.Keys) {
    $base = Get-CertBase $set
    $rootSub = Get-CertField (Join-Path $base "root.crt") "subject"
    $yunSub = Get-CertField (Join-Path $base "yunying.crt") "subject"
    $yunIss = Get-CertField (Join-Path $base "yunying.crt") "issuer"
    $sigIss = Get-CertField (Join-Path $base "user_sig.crt") "issuer"
    $encIss = Get-CertField (Join-Path $base "user_enc.crt") "issuer"

    $ok1 = ($yunIss -eq $rootSub)
    $ok2 = ($sigIss -eq $yunSub)
    $ok3 = ($encIss -eq $yunSub)
    if (-not ($ok1 -and $ok2 -and $ok3)) { $metaFail++ }
    $color = if ($ok1 -and $ok2 -and $ok3) { "Green" } else { "Red" }
    Write-Host ("{0}: root<-yunying={1}, yunying<-user_sig={2}, yunying<-user_enc={3}" -f $set, $ok1, $ok2, $ok3) -ForegroundColor $color
}

Write-Host ""
Write-Host "=== notAfter (expiry) ===" -ForegroundColor Cyan
foreach ($set in $CertSets.Keys) {
    $base = Get-CertBase $set
    foreach ($name in $names) {
        $f = Join-Path $base "$name.crt"
        $nb = Get-CertField $f "startdate"
        $na = Get-CertField $f "enddate"
        Write-Host ("  {0}/{1}.crt : {2} -> {3}" -f $set, $name, $nb, $na)
    }
}

if ($viewFail -ne 0 -or $asnFail -ne 0 -or $metaFail -ne 0) {
    Write-Host ""
    Write-Host ("Acceptance FAILED (parse={0}, asn1={1}, meta={2})." -f $viewFail, $asnFail, $metaFail) -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Acceptance OK. For crypto verify run: .\verify-chain-all.ps1" -ForegroundColor Green
exit 0
