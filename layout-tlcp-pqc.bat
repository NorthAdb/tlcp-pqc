@echo off
setlocal

set "TLCP_ROOT=D:\20240429certificate-verification\tlcp-pqc"

mkdir "%TLCP_ROOT%\bin" 2>nul
mkdir "%TLCP_ROOT%\lib" 2>nul
mkdir "%TLCP_ROOT%\providers" 2>nul
mkdir "%TLCP_ROOT%\config" 2>nul

REM Windows install_sw puts runtime DLLs in tongsuo-install\bin (same dir as openssl.exe)
copy /Y "%TLCP_ROOT%\tongsuo-install\bin\openssl.exe" "%TLCP_ROOT%\bin\" >nul
if errorlevel 1 (
    echo ERROR: tongsuo-install\bin\openssl.exe not found. Run build-tongsuo.bat first.
    exit /b 1
)
copy /Y "%TLCP_ROOT%\tongsuo-install\bin\libcrypto-3-x64.dll" "%TLCP_ROOT%\bin\" >nul
copy /Y "%TLCP_ROOT%\tongsuo-install\bin\libssl-3-x64.dll" "%TLCP_ROOT%\bin\" >nul
copy /Y "%TLCP_ROOT%\pqmagic-install\lib\libpqmagic_std.lib" "%TLCP_ROOT%\lib\" >nul 2>nul

copy /Y "%TLCP_ROOT%\pqmagic-algorithms-provider\build\Release\pqmagic.dll" "%TLCP_ROOT%\providers\" >nul
copy /Y "%TLCP_ROOT%\x509-hybrid-spki-provider\build\Release\libml_dsa_sm2_provider.dll" "%TLCP_ROOT%\providers\" >nul
copy /Y "%TLCP_ROOT%\x509-hybrid-verify-provider\build\Release\cert_verify.dll" "%TLCP_ROOT%\providers\" >nul
if exist "%TLCP_ROOT%\ntls-aigis-provider\build\Release\aigis_enc.dll" (
    copy /Y "%TLCP_ROOT%\ntls-aigis-provider\build\Release\aigis_enc.dll" "%TLCP_ROOT%\providers\" >nul
)
if exist "%TLCP_ROOT%\x509-hybrid-verify-provider\build\Release\verify_certs.exe" (
    copy /Y "%TLCP_ROOT%\x509-hybrid-verify-provider\build\Release\verify_certs.exe" "%TLCP_ROOT%\bin\" >nul
)

if not exist "%TLCP_ROOT%\config\openssl-all-providers.cnf" (
    >"%TLCP_ROOT%\config\openssl-all-providers.cnf" (
        echo config_diagnostics = 0
        echo openssl_conf = openssl_init
        echo.
        echo [openssl_init]
        echo providers = provider_sect
        echo.
        echo [provider_sect]
        echo default = default_sect
        echo pqmagic = pqmagic_sect
        echo ml_dsa_sm2 = ml_dsa_sm2_sect
        echo cert_verify = cert_verify_sect
        echo aigis_enc = aigis_enc_sect
        echo.
        echo [default_sect]
        echo activate = 1
        echo.
        echo [pqmagic_sect]
        echo module = D:/20240429certificate-verification/tlcp-pqc/providers/pqmagic.dll
        echo activate = 1
        echo.
        echo [ml_dsa_sm2_sect]
        echo module = D:/20240429certificate-verification/tlcp-pqc/providers/libml_dsa_sm2_provider.dll
        echo activate = 1
        echo.
        echo [cert_verify_sect]
        echo module = D:/20240429certificate-verification/tlcp-pqc/providers/cert_verify.dll
        echo activate = 1
        echo.
        echo [aigis_enc_sect]
        echo module = D:/20240429certificate-verification/tlcp-pqc/providers/aigis_enc.dll
        echo activate = 1
    )
)

exit /b 0
