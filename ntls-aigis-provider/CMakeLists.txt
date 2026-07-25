cmake_minimum_required(VERSION 3.10)
project(aigis_enc_openssl_provider C)

set(TLCP_ROOT "D:/20240429certificate-verification/tlcp-pqc" CACHE PATH "tlcp-pqc root")
set(TONGSUO_ROOT "${TLCP_ROOT}/tongsuo-install" CACHE PATH "Tongsuo install prefix")
set(PQMAGIC_PREFIX "${TLCP_ROOT}/pqmagic-install" CACHE PATH "PQMagic install prefix")

find_library(PQMAGIC_LIB NAMES pqmagic_std libpqmagic_std
    PATHS "${PQMAGIC_PREFIX}/lib" NO_DEFAULT_PATH)
if(NOT PQMAGIC_LIB)
    find_library(PQMAGIC_LIB NAMES pqmagic_std libpqmagic_std)
endif()
if(NOT PQMAGIC_LIB)
    message(FATAL_ERROR "libpqmagic_std not found; build PQMagic with ENABLE_AIGIS_ENC=ON first")
endif()

find_library(TONGSUO_CRYPTO NAMES libcrypto libcrypto-3-x64
    PATHS "${TONGSUO_ROOT}/lib" NO_DEFAULT_PATH REQUIRED)

add_library(aigis_enc MODULE src/aigis_enc_prov.c)
set_target_properties(aigis_enc PROPERTIES PREFIX "" OUTPUT_NAME "aigis_enc")
if(WIN32)
    set_target_properties(aigis_enc PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

target_include_directories(aigis_enc PRIVATE
    "${PQMAGIC_PREFIX}/include"
    "${TONGSUO_ROOT}/include")

target_link_directories(aigis_enc PRIVATE "${TONGSUO_ROOT}/lib")
if(MSVC)
    target_link_libraries(aigis_enc PRIVATE ${TONGSUO_CRYPTO})
    target_link_options(aigis_enc PRIVATE "/WHOLEARCHIVE:${PQMAGIC_LIB}")
    target_link_libraries(aigis_enc PRIVATE ${PQMAGIC_LIB})
    target_compile_options(aigis_enc PRIVATE /W3 /utf-8)
else()
    target_link_libraries(aigis_enc PRIVATE ${TONGSUO_CRYPTO} ${PQMAGIC_LIB})
    target_compile_options(aigis_enc PRIVATE -Wall -Wextra)
endif()

option(BUILD_TEST_AIGIS_KEM "Build test_aigis_kem tool" OFF)
if(BUILD_TEST_AIGIS_KEM)
    add_executable(test_aigis_kem tools/test_aigis_kem.c)
    target_include_directories(test_aigis_kem PRIVATE "${TONGSUO_ROOT}/include")
    target_link_directories(test_aigis_kem PRIVATE "${TONGSUO_ROOT}/lib")
    target_link_libraries(test_aigis_kem PRIVATE ${TONGSUO_CRYPTO})
    target_compile_definitions(test_aigis_kem PRIVATE
        AIGIS_ENC_PROVIDER_SO="$<TARGET_FILE:aigis_enc>")
    add_dependencies(test_aigis_kem aigis_enc)
endif()
