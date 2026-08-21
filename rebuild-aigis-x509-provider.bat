@echo off
setlocal EnableDelayedExpansion

set "TLCP_ROOT=D:\20240429certificate-verification\tlcp-pqc"
set "CMAKE=D:\DevTools\Strawberry\c\bin\cmake.exe"
set "VCVARS=D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

call "%VCVARS%" >nul
if errorlevel 1 exit /b 1
set "PATH=D:\DevTools\Strawberry\perl\bin;%PATH%"
set "CL=/utf-8"

echo === [1/3] Rebuild PQMagic with Aigis-SIG1 + Enc-1/2 ===
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
copy /Y "%TLCP_ROOT%\pqmagic\include\pqmagic_api.h" "%TLCP_ROOT%\pqmagic-install\include\" >nul
copy /Y "%TLCP_ROOT%\lib\libpqmagic_std.lib" "%TLCP_ROOT%\lib\libpqmagic_std.lib.bak" >nul 2>nul
copy /Y "%TLCP_ROOT%\pqmagic\build\Release\libpqmagic_std.lib" "%TLCP_ROOT%\lib\" >nul

echo === [2/3] Rebuild pqmagic.dll (static PQMagic) ===
if not exist "%TLCP_ROOT%\pqmagic-algorithms-provider\build" mkdir "%TLCP_ROOT%\pqmagic-algorithms-provider\build"
cd /d "%TLCP_ROOT%\pqmagic-algorithms-provider\build"
if not exist CMakeCache.txt (
    "%CMAKE%" .. -G "Visual Studio 17 2022" -A x64
    if errorlevel 1 exit /b 1
)
"%CMAKE%" --build . --config Release --target pqmagic
if errorlevel 1 exit /b 1

echo === [3/3] Build aigis-provider ===
if exist "%TLCP_ROOT%\aigis-provider\build" rmdir /s /q "%TLCP_ROOT%\aigis-provider\build"
mkdir "%TLCP_ROOT%\aigis-provider\build"
cd /d "%TLCP_ROOT%\aigis-provider\build"
"%CMAKE%" .. -G "Visual Studio 17 2022" -A x64
if errorlevel 1 exit /b 1
"%CMAKE%" --build . --config Release
if errorlevel 1 exit /b 1

copy /Y "%TLCP_ROOT%\aigis-provider\build\Release\aigis.dll" "%TLCP_ROOT%\providers\" >nul
copy /Y "%TLCP_ROOT%\aigis-provider\build\Release\aigis_cert_tool.exe" "%TLCP_ROOT%\bin\" >nul
copy /Y "%TLCP_ROOT%\pqmagic-algorithms-provider\build\Release\pqmagic.dll" "%TLCP_ROOT%\providers\" >nul
copy /Y "%TLCP_ROOT%\bin\libcrypto-3-x64.dll" "%TLCP_ROOT%\aigis-provider\build\Release\" >nul 2>nul

echo === DONE: providers\aigis.dll + bin\aigis_cert_tool.exe ===
exit /b 0
