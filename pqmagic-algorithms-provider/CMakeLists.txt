cmake_minimum_required(VERSION 3.10)
project(pqmagic_openssl_provider C)

set(TLCP_ROOT "D:/20240429certificate-verification/tlcp-pqc" CACHE PATH "tlcp-pqc root")
set(TONGSUO_ROOT "${TLCP_ROOT}/tongsuo-install" CACHE PATH "Tongsuo install prefix")
set(PQMAGIC_PREFIX "${TLCP_ROOT}/pqmagic-install" CACHE PATH "PQMagic install prefix")

find_library(PQMAGIC_LIB NAMES pqmagic_std libpqmagic_std
    PATHS "${PQMAGIC_PREFIX}/lib" NO_DEFAULT_PATH)
if(NOT PQMAGIC_LIB)
    find_library(PQMAGIC_LIB NAMES pqmagic_std libpqmagic_std)
endif()
if(NOT PQMAGIC_LIB)
    message(FATAL_ERROR "libpqmagic_std not found; build & install PQMagic first")
endif()

find_library(TONGSUO_CRYPTO NAMES libcrypto libcrypto-3-x64
    PATHS "${TONGSUO_ROOT}/lib" NO_DEFAULT_PATH REQUIRED)

add_library(pqmagic MODULE pqmagic_prov.c)
set_target_properties(pqmagic PROPERTIES PREFIX "" OUTPUT_NAME "pqmagic")

target_include_directories(pqmagic PRIVATE
    "${PQMAGIC_PREFIX}/include"
    "${TONGSUO_ROOT}/include")

target_link_directories(pqmagic PRIVATE "${TONGSUO_ROOT}/lib")
if(MSVC)
    target_link_libraries(pqmagic PRIVATE ${TONGSUO_CRYPTO})
    target_link_options(pqmagic PRIVATE "/WHOLEARCHIVE:${PQMAGIC_LIB}")
    target_link_libraries(pqmagic PRIVATE ${PQMAGIC_LIB})
else()
    target_link_libraries(pqmagic PRIVATE ${TONGSUO_CRYPTO} ${PQMAGIC_LIB})
endif()

if(MSVC)
    target_compile_options(pqmagic PRIVATE /W3 /utf-8)
else()
    target_compile_options(pqmagic PRIVATE -Wall)
endif()
