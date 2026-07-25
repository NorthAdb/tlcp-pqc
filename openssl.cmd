@echo off
setlocal EnableExtensions
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
if not defined OPENSSL_CONF set "OPENSSL_CONF=%ROOT%\config\openssl-all-providers.cnf"
if not defined OPENSSL_MODULES set "OPENSSL_MODULES=%ROOT%\providers"
"%ROOT%\bin\openssl.exe" %*
