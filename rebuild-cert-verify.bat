@echo off
call "D:\DevTools\VS2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
set CL=/utf-8
cd /d D:\20240429certificate-verification\tlcp-pqc\x509-hybrid-verify-provider\build
"D:\DevTools\Strawberry\c\bin\cmake.exe" ..
"D:\DevTools\Strawberry\c\bin\cmake.exe" --build . --config Release --target cert_verify
copy /Y Release\cert_verify.dll D:\20240429certificate-verification\tlcp-pqc\providers\
