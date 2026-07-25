@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
set PATH=C:\Strawberry\perl\bin;%PATH%
set CL=/utf-8
cd /d D:\20240429certificate-verification\tlcp-pqc\Tongsuo

echo === nmake build_libs ===
nmake build_libs
if errorlevel 1 exit /b 1

echo === nmake build_apps ===
nmake build_apps
if errorlevel 1 exit /b 1

echo === nmake install_sw ===
nmake install_sw
if errorlevel 1 exit /b 1

echo === DONE ===
apps\openssl.exe version
exit /b 0
