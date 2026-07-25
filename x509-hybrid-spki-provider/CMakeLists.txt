cmake_minimum_required(VERSION 3.10)
project(ml_dsa_sm2_provider C)

set(TLCP_ROOT "D:/20240429certificate-verification/tlcp-pqc" CACHE PATH "tlcp-pqc root")
set(TONGSUO_ROOT "${TLCP_ROOT}/tongsuo-install" CACHE PATH "Tongsuo install prefix")
set(TONGSUO_SOURCE "${TLCP_ROOT}/Tongsuo" CACHE PATH "Tongsuo source tree")

find_library(TONGSUO_CRYPTO NAMES libcrypto libcrypto-3-x64
    PATHS "${TONGSUO_ROOT}/lib" NO_DEFAULT_PATH REQUIRED)
find_library(TONGSUO_SSL NAMES libssl libssl-3-x64
    PATHS "${TONGSUO_ROOT}/lib" NO_DEFAULT_PATH REQUIRED)

add_library(ml_dsa_sm2_provider MODULE
    src/ml_dsa_sm2_ameth.c
    src/ml_kem512_sm2_ameth.c
    src/ml_dsa_sm2_provider.c)

set_target_properties(ml_dsa_sm2_provider PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "ml_dsa_sm2_provider")

target_include_directories(ml_dsa_sm2_provider PRIVATE
    include
    "${TONGSUO_ROOT}/include"
    "${TONGSUO_SOURCE}/include")

target_link_directories(ml_dsa_sm2_provider PRIVATE "${TONGSUO_ROOT}/lib")
target_link_libraries(ml_dsa_sm2_provider PRIVATE ${TONGSUO_CRYPTO} ${TONGSUO_SSL})

if(MSVC)
    target_compile_options(ml_dsa_sm2_provider PRIVATE /W3 /utf-8)
else()
    target_compile_options(ml_dsa_sm2_provider PRIVATE -Wall)
endif()
