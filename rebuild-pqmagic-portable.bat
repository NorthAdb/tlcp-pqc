@echo off
setlocal EnableDelayedExpansion

set "TLCP_ROOT=D:\20240429certificate-verification\tlcp-pqc"
set "CMAKE=C:\Program Files\CMake\bin\cmake.exe"
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

call "%VCVARS%" >nul
if errorlevel 1 exit /b 1
set "PATH=C:\Strawberry\perl\bin;%PATH%"
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
    -DENABLE_AIGIS_SIG=OFF ^
    -DENABLE_SLH_DSA=OFF ^
    -DENABLE_SPHINCS_A=OFF ^
    -DML_KEM_MODES=512 ^
    -DML_DSA_MODES=44 ^
    -DAIGIS_ENC_MODES=2 ^
    -DENABLE_BENCH=OFF ^
    -DENABLE_TEST=OFF ^
    -DPQMAGIC_MSVC_PORTABLE=ON
if errorlevel 1 exit /b 1

echo === Rebuild libpqmagic_std.lib ===
"%CMAKE%" --build . --config Release --target pqmagic_static_target --clean-first
if errorlevel 1 exit /b 1
copy /Y "%TLCP_ROOT%\pqmagic\build\Release\libpqmagic_std.lib" "%TLCP_ROOT%\pqmagic-install\lib\" >nul

echo === Rebuild providers ===
for %%P in (pqmagic-algorithms-provider x509-hybrid-spki-provider x509-hybrid-verify-provider ntls-aigis-provider) do (
    echo --- %%P ---
    cd /d "%TLCP_ROOT%\%%P\build"
    "%CMAKE%" --build . --config Release --clean-first
    if errorlevel 1 exit /b 1
)

call "%~dp0layout-tlcp-pqc.bat"
echo === DONE ===
exit /b 0
