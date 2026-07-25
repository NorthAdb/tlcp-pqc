@echo off
setlocal EnableExtensions
set "ROOT=D:\20240429certificate-verification\tlcp-pqc"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
set PATH=C:\Strawberry\perl\bin;%PATH%
set CL=/utf-8
cd /d "%ROOT%\Tongsuo"
del /F /Q makefile makefile.new 2>nul
perl Configure VC-WIN64A --prefix=%ROOT%\tongsuo-install enable-ntls no-tests no-makedepend no-asm
if errorlevel 1 exit /b 1
if exist makefile.new copy /Y makefile.new makefile >nul
nmake crypto\x509\libcrypto-shlib-x_pubkey.obj crypto\x509\libcrypto-shlib-x509_pqc_hybrid_vfy.obj
if errorlevel 1 exit /b 1
nmake libcrypto-3-x64.dll
if errorlevel 1 exit /b 1
nmake apps\openssl.exe
if errorlevel 1 exit /b 1
copy /Y libcrypto-3-x64.dll "%ROOT%\bin\" >nul
copy /Y libcrypto-3-x64.dll apps\ >nul
copy /Y apps\openssl.exe "%ROOT%\bin\" >nul
exit /b 0
