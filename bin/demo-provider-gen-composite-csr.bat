@echo off
setlocal EnableExtensions
set "ROOT=D:\20240429certificate-verification\tlcp-pqc"
set "OUT=%ROOT%\certs\_provider_gen_composite"
set "OPENSSL_CONF=%ROOT%\config\openssl-all-providers.cnf"
set "OPENSSL_MODULES=%ROOT%\providers"

if not exist "%OUT%" mkdir "%OUT%"
cd /d "%ROOT%"

echo === [1/4] openssl version ===
"%ROOT%\bin\openssl.exe" version
if errorlevel 1 exit /b 1

echo === [2/4] genpkey ML-DSA-44-SPKI + SM2 ===
"%ROOT%\bin\openssl.exe" genpkey -algorithm id-ML-DSA-44-SPKI -out "%OUT%\demo.mldsa.key"
if errorlevel 1 exit /b 1
"%ROOT%\bin\openssl.exe" genpkey -algorithm SM2 -out "%OUT%\demo.sm2.key"
if errorlevel 1 exit /b 1

echo === [3/4] req -new -key -sm2key (composite CSR) ===
"%ROOT%\bin\openssl.exe" req -new -key "%OUT%\demo.mldsa.key" -sm2key "%OUT%\demo.sm2.key" -subj "/C=CN/ST=Beijing/O=TLCP-PQC/OU=Demo/CN=ProviderGenComposite" -out "%OUT%\demo.csr"
if errorlevel 1 exit /b 1

echo === [4/4] req -verify ===
"%ROOT%\bin\openssl.exe" req -in "%OUT%\demo.csr" -verify -noout
if errorlevel 1 exit /b 1

echo === DONE ===
exit /b 0