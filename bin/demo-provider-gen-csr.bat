@echo off
setlocal EnableExtensions
set "ROOT=D:\20240429certificate-verification\tlcp-pqc"
set "VCVARS=D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
set "CMAKE=D:\DevTools\Strawberry\c\bin\cmake.exe"

call "%VCVARS%" >nul
if errorlevel 1 exit /b 1
set "PATH=D:\DevTools\Strawberry\perl\bin;%PATH%"
set "CL=/utf-8"

echo === [1/3] Build pqmagic provider ===
cd /d "%ROOT%\pqmagic-algorithms-provider\build"
"%CMAKE%" --build . --config Release
if errorlevel 1 exit /b 1
copy /Y "%ROOT%\pqmagic-algorithms-provider\build\Release\pqmagic.dll" "%ROOT%\providers\" >nul

echo === [2/3] Build Tongsuo libcrypto + apps ===
cd /d "%ROOT%\Tongsuo"
if exist makefile.new copy /Y makefile.new makefile >nul
attrib -R makefile 2>nul

set /a n=0
:libs
set /a n+=1
if %n% GTR 15 exit /b 1
if exist makefile.new copy /Y makefile.new makefile >nul
nmake build_libs
if exist libcrypto-3-x64.dll goto apps
goto libs

:apps
set /a m=0
:apps_loop
set /a m+=1
if %m% GTR 10 exit /b 1
nmake build_apps
if exist apps\openssl.exe goto install
goto apps_loop

:install
nmake install_sw
copy /Y "%ROOT%\Tongsuo\libcrypto-3-x64.dll" "%ROOT%\bin\" >nul
copy /Y "%ROOT%\Tongsuo\apps\openssl.exe" "%ROOT%\bin\" >nul
copy /Y "%ROOT%\Tongsuo\libcrypto-3-x64.dll" "%ROOT%\Tongsuo\apps\" >nul

echo === [3/3] Generate key + CSR ===
set "OUT=%ROOT%\certs\_provider_gen"
if not exist "%OUT%" mkdir "%OUT%"
set "OPENSSL_CONF=%ROOT%\config\openssl-all-providers.cnf"
cd /d "%ROOT%"

"%ROOT%\bin\openssl.exe" version
"%ROOT%\bin\openssl.exe" genpkey -algorithm id-ML-DSA-44-SPKI -out "%OUT%\mldsa.key"
if errorlevel 1 exit /b 1
"%ROOT%\bin\openssl.exe" pkey -in "%OUT%\mldsa.key" -text -noout > "%OUT%\key_info.txt"
"%ROOT%\bin\openssl.exe" req -new -key "%OUT%\mldsa.key" -subj "/C=CN/ST=Beijing/O=Demo/CN=provider-gen.demo" -out "%OUT%\demo.csr"
if errorlevel 1 exit /b 1
"%ROOT%\bin\openssl.exe" req -in "%OUT%\demo.csr" -text -noout > "%OUT%\csr_info.txt"
"%ROOT%\bin\openssl.exe" req -in "%OUT%\demo.csr" -verify -noout > "%OUT%\verify.txt" 2>&1
type "%OUT%\verify.txt"
echo === DONE ===
exit /b 0
