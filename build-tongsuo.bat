@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 (
    echo ERROR: vcvars64.bat failed
    exit /b 1
)
set PATH=C:\Strawberry\perl\bin;%PATH%
set CL=/utf-8
cd /d D:\20240429certificate-verification\tlcp-pqc\Tongsuo

echo === perl Configure ===
perl Configure VC-WIN64A --prefix=D:\20240429certificate-verification\tlcp-pqc\tongsuo-install enable-ntls no-tests no-makedepend no-asm
if errorlevel 1 (
    echo ERROR: Configure failed
    exit /b 1
)

echo === nmake build_libs build_apps ===
nmake build_libs build_apps
if errorlevel 1 (
    echo ERROR: nmake failed
    exit /b 1
)

echo === nmake install_sw ===
nmake install_sw
if errorlevel 1 (
    echo ERROR: install_sw failed
    exit /b 1
)

echo === DONE ===
apps\openssl.exe version -a
exit /b 0
