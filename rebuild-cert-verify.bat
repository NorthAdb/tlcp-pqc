@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
set CL=/utf-8
cd /d D:\20240429certificate-verification\tlcp-pqc\x509-hybrid-verify-provider\build
"C:\Program Files\CMake\bin\cmake.exe" ..
"C:\Program Files\CMake\bin\cmake.exe" --build . --config Release --target cert_verify
copy /Y Release\cert_verify.dll D:\20240429certificate-verification\tlcp-pqc\providers\
