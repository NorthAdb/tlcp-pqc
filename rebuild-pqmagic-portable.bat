@echo off
setlocal EnableDelayedExpansion

set "TLCP_ROOT=D:\20240429certificate-verification\tlcp-pqc"
set "CMAKE=D:\DevTools\Strawberry\c\bin\cmake.exe"
set "VCVARS=D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

call "%VCVARS%" >nul
if errorlevel 1 exit /b 1
set "PATH=D:\DevTools\Strawberry\perl\bin;%PATH%"
set "CL=/utf-8"

echo === Reconfigure PQMagic (portable MSVC, no AVX512) ===
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

echo === Rebuild libpqmagic_std.lib ===
"%CMAKE%" --build . --config Release --target pqmagic_static_target --clean-first
if errorlevel 1 exit /b 1
copy /Y "%TLCP_ROOT%\pqmagic\build\Release\libpqmagic_std.lib" "%TLCP_ROOT%\pqmagic-install\lib\" >nul

echo === Rebuild providers ===
for %%P in (pqmagic-algorithms-provider x509-hybrid-spki-provider x509-hybrid-verify-provider aigis-provider) do (
    echo --- %%P ---
    if not exist "%TLCP_ROOT%\%%P\build" mkdir "%TLCP_ROOT%\%%P\build"
    cd /d "%TLCP_ROOT%\%%P\build"
    if not exist CMakeCache.txt (
        "%CMAKE%" .. -G "Visual Studio 17 2022" -A x64
        if errorlevel 1 exit /b 1
    )
    "%CMAKE%" --build . --config Release
    if errorlevel 1 exit /b 1
)

call "%~dp0layout-tlcp-pqc.bat"
echo === DONE ===
exit /b 0
