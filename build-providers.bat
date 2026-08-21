@echo off
setlocal EnableDelayedExpansion

set "TLCP_ROOT=D:\20240429certificate-verification\tlcp-pqc"
set "CMAKE=D:\DevTools\Strawberry\c\bin\cmake.exe"
set "VCVARS=D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

call "%VCVARS%" >nul
if errorlevel 1 exit /b 1
set "PATH=D:\DevTools\Strawberry\perl\bin;%PATH%"
set "CL=/utf-8"

echo === [1/4] Build PQMagic ===
if exist "%TLCP_ROOT%\pqmagic\build" rmdir /s /q "%TLCP_ROOT%\pqmagic\build"
mkdir "%TLCP_ROOT%\pqmagic\build"
cd /d "%TLCP_ROOT%\pqmagic\build"
"%CMAKE%" .. -G "Visual Studio 17 2022" -A x64 ^
    -DCMAKE_INSTALL_PREFIX="%TLCP_ROOT%\pqmagic-install" ^
    -DUSE_SHAKE=ON ^
    -DENABLE_KYBER=OFF ^
    -DENABLE_ML_KEM=ON ^
    -DENABLE_AIGIS_ENC=ON ^
    -DENABLE_DILITHIUM=OFF ^
    -DENABLE_ML_DSA=ON ^
    -DENABLE_AIGIS_SIG=ON ^
    -DENABLE_SLH_DSA=OFF ^
    -DENABLE_SPHINCS_A=OFF ^
    -DML_KEM_MODES=512 ^
    -DML_DSA_MODES=44 ^
    -DAIGIS_ENC_MODES=1 ^
    -DAIGIS_SIG_MODES=1 ^
    -DENABLE_BENCH=OFF ^
    -DENABLE_TEST=OFF ^
    -DPQMAGIC_MSVC_PORTABLE=ON
if errorlevel 1 exit /b 1
"%CMAKE%" --build . --config Release --target pqmagic_static_target
if errorlevel 1 exit /b 1
mkdir "%TLCP_ROOT%\pqmagic-install\lib" 2>nul
mkdir "%TLCP_ROOT%\pqmagic-install\include" 2>nul
copy /Y "%TLCP_ROOT%\pqmagic\build\Release\libpqmagic_std.lib" "%TLCP_ROOT%\pqmagic-install\lib\" >nul
if not exist "%TLCP_ROOT%\pqmagic-install\include\pqmagic_api.h" (
    copy /Y "%TLCP_ROOT%\pqmagic\include\pqmagic_api.h" "%TLCP_ROOT%\pqmagic-install\include\" >nul
)

echo === [2/4] Build pqmagic-algorithms-provider ===
if exist "%TLCP_ROOT%\pqmagic-algorithms-provider\build" rmdir /s /q "%TLCP_ROOT%\pqmagic-algorithms-provider\build"
mkdir "%TLCP_ROOT%\pqmagic-algorithms-provider\build"
cd /d "%TLCP_ROOT%\pqmagic-algorithms-provider\build"
"%CMAKE%" .. -G "Visual Studio 17 2022" -A x64
if errorlevel 1 exit /b 1
"%CMAKE%" --build . --config Release
if errorlevel 1 exit /b 1

echo === [3/4] Build x509-hybrid-spki-provider ===
if exist "%TLCP_ROOT%\x509-hybrid-spki-provider\build" rmdir /s /q "%TLCP_ROOT%\x509-hybrid-spki-provider\build"
mkdir "%TLCP_ROOT%\x509-hybrid-spki-provider\build"
cd /d "%TLCP_ROOT%\x509-hybrid-spki-provider\build"
"%CMAKE%" .. -G "Visual Studio 17 2022" -A x64
if errorlevel 1 exit /b 1
"%CMAKE%" --build . --config Release
if errorlevel 1 exit /b 1

echo === [4/4] Build x509-hybrid-verify-provider ===
if exist "%TLCP_ROOT%\x509-hybrid-verify-provider\build" rmdir /s /q "%TLCP_ROOT%\x509-hybrid-verify-provider\build"
mkdir "%TLCP_ROOT%\x509-hybrid-verify-provider\build"
cd /d "%TLCP_ROOT%\x509-hybrid-verify-provider\build"
"%CMAKE%" .. -G "Visual Studio 17 2022" -A x64
if errorlevel 1 exit /b 1
"%CMAKE%" --build . --config Release
if errorlevel 1 exit /b 1

echo === Layout runtime files ===
call "%~dp0layout-tlcp-pqc.bat"
if errorlevel 1 exit /b 1

echo === DONE ===
echo NOTE: aigis.dll 请用 rebuild-aigis-x509-provider.bat 构建（证书 X.509 / SIG1+ENC1）。
exit /b 0
