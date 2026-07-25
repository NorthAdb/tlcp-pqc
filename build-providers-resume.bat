@echo off
setlocal EnableDelayedExpansion
set "TLCP_ROOT=D:\20240429certificate-verification\tlcp-pqc"
set "CMAKE=C:\Program Files\CMake\bin\cmake.exe"
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
call "%VCVARS%" >nul
set "PATH=C:\Strawberry\perl\bin;%PATH%"
set "CL=/utf-8"

echo === [3/4] Build x509-hybrid-spki-provider ===
if exist "%TLCP_ROOT%\x509-hybrid-spki-provider\build" rmdir /s /q "%TLCP_ROOT%\x509-hybrid-spki-provider\build"
mkdir "%TLCP_ROOT%\x509-hybrid-spki-provider\build"
cd /d "%TLCP_ROOT%\x509-hybrid-spki-provider\build"
"%CMAKE%" .. -G "Visual Studio 17 2022" -A x64
if errorlevel 1 exit /b 1
"%CMAKE%" --build . --config Release
if errorlevel 1 exit /b 1

echo === [4/5] Build x509-hybrid-verify-provider ===
cd /d "%TLCP_ROOT%\x509-hybrid-verify-provider\build"
"%CMAKE%" --build . --config Release --target cert_verify
if errorlevel 1 exit /b 1

echo === [5/5] Build ntls-aigis-provider ===
if not exist "%TLCP_ROOT%\ntls-aigis-provider\build" mkdir "%TLCP_ROOT%\ntls-aigis-provider\build"
cd /d "%TLCP_ROOT%\ntls-aigis-provider\build"
if not exist CMakeCache.txt (
    "%CMAKE%" .. -G "Visual Studio 17 2022" -A x64
    if errorlevel 1 exit /b 1
)
"%CMAKE%" --build . --config Release --target aigis_enc
if errorlevel 1 exit /b 1

call "%~dp0layout-tlcp-pqc.bat"
echo === DONE ===
exit /b 0
