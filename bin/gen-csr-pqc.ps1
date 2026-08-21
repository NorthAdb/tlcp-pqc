<#
.SYNOPSIS
  生成纯 PQC PKCS#10 CSR（Pure PQC Certificate\mlkemdsa）。

  使用 PKCS#8 私钥 + 证书中的 Subject/SPKI，签名依赖 mldsa_sign_sm3.exe。
  openssl req -new 目前不支持 ML-DSA-44-SPKI，故不走 req -new。

.EXAMPLE
  .\gen-csr-pqc.ps1
  .\gen-csr-pqc.ps1 -Key "..\certs\Pure PQC Certificate\mlkemdsa\user_sig_pkcs8.pem" -Cert "..\certs\Pure PQC Certificate\mlkemdsa\user_sig.crt" -Out "..\certs\Pure PQC Certificate\mlkemdsa\csr\user_sig.csr"
#>
param(
    [string]$Key = "",
    [string]$Cert = "",
    [string]$Out = "",
    [ValidateSet("root", "yunying", "user_sig", "all")]
    [string]$Name = "all"
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\Set-TlcpEnv.ps1"

$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) {
    $py = Get-Command python3 -ErrorAction SilentlyContinue
}
if (-not $py) {
    Write-Error "未找到 python / python3"
    exit 1
}

$script = Join-Path $PSScriptRoot "gen-csr-certs1.py"
$signer = Join-Path $PSScriptRoot "mldsa_sign_sm3.exe"
$certsDir = Join-Path $env:TLCP_ROOT "certs\Pure PQC Certificate\mlkemdsa"

if (-not (Test-Path $signer)) {
    Write-Host "未找到 mldsa_sign_sm3.exe，正在编译..." -ForegroundColor Yellow
    & (Join-Path $PSScriptRoot "build-mldsa-sign.bat")
    if (-not $?) { exit 1 }
}

$argsList = @(
    $script,
    "--openssl", $env:OPENSSL,
    "--signer", $signer
)

if ($Key -and $Cert) {
    $argsList += @("--key", $Key)
    $argsList += @("--cert", $Cert)
    if ($Out) { $argsList += @("--out", $Out) }
} elseif ($Name -ne "all") {
    $argsList += @("--names", $Name)
} else {
    $argsList += @("--certs-dir", $certsDir)
}

& $py.Source @argsList
if (-not $?) { exit 1 }

# 单文件模式：用 Tongsuo 验签
if ($Key -and $Cert) {
    $csrPath = $Out
    if (-not $csrPath) {
        $csrPath = Join-Path (Split-Path -Parent $Key) "$( [System.IO.Path]::GetFileNameWithoutExtension($Cert) ).csr"
    }
    if (Test-Path $csrPath) {
        Write-Host "`n=== openssl req -verify ===" -ForegroundColor Cyan
        & $env:OPENSSL req -in $csrPath -verify -noout
        if (-not $?) { exit 1 }
    }
}
