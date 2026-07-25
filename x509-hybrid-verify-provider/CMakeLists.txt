cmake_minimum_required(VERSION 3.10)
project(cert_verify C)

set(TLCP_ROOT "D:/20240429certificate-verification/tlcp-pqc" CACHE PATH "tlcp-pqc root")
set(TONGSUO_ROOT "${TLCP_ROOT}/tongsuo-install" CACHE PATH "Tongsuo install prefix")
set(TONGSUO_SOURCE "${TLCP_ROOT}/Tongsuo" CACHE PATH "Tongsuo source tree")
set(PQMAGIC_PREFIX "${TLCP_ROOT}/pqmagic-install" CACHE PATH "PQMagic install prefix")

find_library(TONGSUO_CRYPTO NAMES libcrypto libcrypto-3-x64
    PATHS "${TONGSUO_ROOT}/lib" NO_DEFAULT_PATH REQUIRED)

set(CERT_VERIFY_SOURCES
    src/cert_verify.c
    src/cert_verify_prov.c)

if(WIN32)
    list(APPEND CERT_VERIFY_SOURCES src/cert_verify_openssl_win.c)
else()
    list(APPEND CERT_VERIFY_SOURCES src/cert_verify_openssl.c)
endif()

add_library(cert_verify SHARED ${CERT_VERIFY_SOURCES})
set_target_properties(cert_verify PROPERTIES OUTPUT_NAME "cert_verify")
if(WIN32)
    set_target_properties(cert_verify PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

target_include_directories(cert_verify PRIVATE
    include
    "${TONGSUO_ROOT}/include"
    "${TONGSUO_SOURCE}/include"
    "${PQMAGIC_PREFIX}/include")

target_link_directories(cert_verify PRIVATE "${TONGSUO_ROOT}/lib")
target_link_libraries(cert_verify PRIVATE ${TONGSUO_CRYPTO})

if(MSVC)
    target_compile_options(cert_verify PRIVATE /W3 /utf-8)
else()
    target_compile_options(cert_verify PRIVATE -Wall)
endif()

option(BUILD_VERIFY_CERTS_EXE "Build verify_certs_1 CLI" ON)
if(BUILD_VERIFY_CERTS_EXE)
    add_executable(verify_certs tools/verify_certs_1.c src/cert_verify.c)
    target_include_directories(verify_certs PRIVATE
        include
        "${TONGSUO_ROOT}/include"
        "${TONGSUO_SOURCE}/include"
        "${PQMAGIC_PREFIX}/include")
    target_link_directories(verify_certs PRIVATE "${TONGSUO_ROOT}/lib")
    target_link_libraries(verify_certs PRIVATE ${TONGSUO_CRYPTO})
    if(MSVC)
        target_compile_options(verify_certs PRIVATE /W3 /utf-8)
    else()
        target_compile_options(verify_certs PRIVATE -Wall)
    endif()
endif()
