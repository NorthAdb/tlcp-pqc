@echo off
setlocal

set "TLCP_ROOT=D:\20240429certificate-verification\tlcp-pqc"

set "PATH=%TLCP_ROOT%\bin;%TLCP_ROOT%\lib;%PATH%"
set "OPENSSL_CONF=%TLCP_ROOT%\config\openssl-all-providers.cnf"
set "OPENSSL_MODULES=%TLCP_ROOT%\providers"

set "PQMAGIC_PROVIDER=%TLCP_ROOT%\providers\pqmagic.dll"
set "ML_DSA_SM2_PROVIDER=%TLCP_ROOT%\providers\libml_dsa_sm2_provider.dll"
set "PQMAGIC_STD_LIB=%TLCP_ROOT%\providers\pqmagic.dll"
set "CERT_VERIFY_SO=%TLCP_ROOT%\providers\cert_verify.dll"
set "AIGIS_PROVIDER=%TLCP_ROOT%\providers\aigis.dll"
set "CERT_VERIFY_VERIFY_INFO=1"
set "OPENSSL=%TLCP_ROOT%\bin\openssl.exe"

echo TLCP environment loaded: %TLCP_ROOT%
