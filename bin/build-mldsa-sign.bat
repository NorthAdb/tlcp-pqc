@echo off
setlocal EnableDelayedExpansion
set "TLCP_ROOT=D:\20240429certificate-verification\tlcp-pqc"
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

if not exist "%VCVARS%" (
    echo ERROR: vcvars64.bat not found
    exit /b 1
)

call "%VCVARS%"
if errorlevel 1 (
    echo ERROR: vcvars64 failed
    exit /b 1
)
if not defined VCToolsInstallDir (
    echo ERROR: VCToolsInstallDir not set after vcvars64
    exit /b 1
)

set "CL=/utf-8"
set "INC=%TLCP_ROOT%\pqmagic-install\include"
set "LIBPQ=%TLCP_ROOT%\pqmagic-install\lib\libpqmagic_std.lib"
set "SRC=%TLCP_ROOT%\bin\mldsa_sign_sm3.c"
set "OUT=%TLCP_ROOT%\bin\mldsa_sign_sm3.exe"

if not exist "%LIBPQ%" (
    echo ERROR: missing %LIBPQ%
    echo Run build-providers.bat first.
    exit /b 1
)

echo Using VCToolsInstallDir=%VCToolsInstallDir%
cl /nologo /O2 /W3 /MT /I"%INC%" "%SRC%" /Fe:"%OUT%" /link /LTCG "%LIBPQ%" advapi32.lib
set "RC=%ERRORLEVEL%"
if exist "%TLCP_ROOT%\bin\mldsa_sign_sm3.obj" del /q "%TLCP_ROOT%\bin\mldsa_sign_sm3.obj"
if %RC% neq 0 exit /b %RC%

echo === built %OUT% ===
exit /b 0
