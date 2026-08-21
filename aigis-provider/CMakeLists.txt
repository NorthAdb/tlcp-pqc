cmake_minimum_required(VERSION 3.10)
project(aigis_provider C)

set(CMAKE_C_STANDARD 99)

set(TLCP_ROOT "D:/20240429certificate-verification/tlcp-pqc" CACHE PATH "tlcp-pqc root")
set(TONGSUO_ROOT "${TLCP_ROOT}/tongsuo-install" CACHE PATH "Tongsuo install prefix")
set(PQMAGIC_PREFIX "${TLCP_ROOT}/pqmagic-install" CACHE PATH "PQMagic install prefix")

find_library(PQMAGIC_LIB NAMES pqmagic_std libpqmagic_std
    PATHS "${PQMAGIC_PREFIX}/lib" NO_DEFAULT_PATH)
if(NOT PQMAGIC_LIB)
    find_library(PQMAGIC_LIB NAMES pqmagic_std libpqmagic_std)
endif()
if(NOT PQMAGIC_LIB)
    message(FATAL_ERROR "libpqmagic_std not found under ${PQMAGIC_PREFIX}; rebuild PQMagic with ENABLE_AIGIS_SIG=ON and AIGIS_ENC_MODES including 1")
endif()

find_library(TONGSUO_CRYPTO NAMES libcrypto libcrypto-3-x64
    PATHS "${TONGSUO_ROOT}/lib" NO_DEFAULT_PATH REQUIRED)

add_library(aigis MODULE
    src/aigis_prov.c
    src/aigis_cert.c
)
set_target_properties(aigis PROPERTIES PREFIX "" OUTPUT_NAME "aigis")
if(WIN32)
    set_target_properties(aigis PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
    target_compile_definitions(aigis PRIVATE AIGIS_CERT_EXPORTS)
endif()

target_include_directories(aigis PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    "${PQMAGIC_PREFIX}/include"
    "${TONGSUO_ROOT}/include")

target_link_directories(aigis PRIVATE "${TONGSUO_ROOT}/lib")
if(MSVC)
    target_link_libraries(aigis PRIVATE ${TONGSUO_CRYPTO})
    target_link_options(aigis PRIVATE "/WHOLEARCHIVE:${PQMAGIC_LIB}")
    target_link_libraries(aigis PRIVATE ${PQMAGIC_LIB})
    target_compile_options(aigis PRIVATE /W3 /utf-8)
else()
    target_link_libraries(aigis PRIVATE ${TONGSUO_CRYPTO} ${PQMAGIC_LIB})
    target_compile_options(aigis PRIVATE -Wall -fPIC)
endif()

add_executable(aigis_cert_tool
    tools/aigis_cert_tool.c
    src/aigis_cert.c
)
target_compile_definitions(aigis_cert_tool PRIVATE AIGIS_CERT_STATIC)
target_include_directories(aigis_cert_tool PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    "${PQMAGIC_PREFIX}/include"
    "${TONGSUO_ROOT}/include")
target_link_directories(aigis_cert_tool PRIVATE "${TONGSUO_ROOT}/lib")
if(MSVC)
    target_link_libraries(aigis_cert_tool PRIVATE ${TONGSUO_CRYPTO})
    target_link_options(aigis_cert_tool PRIVATE "/WHOLEARCHIVE:${PQMAGIC_LIB}")
    target_link_libraries(aigis_cert_tool PRIVATE ${PQMAGIC_LIB})
    target_compile_options(aigis_cert_tool PRIVATE /W3 /utf-8)
else()
    target_link_libraries(aigis_cert_tool PRIVATE ${TONGSUO_CRYPTO} ${PQMAGIC_LIB})
    target_compile_options(aigis_cert_tool PRIVATE -Wall)
endif()

install(TARGETS aigis LIBRARY DESTINATION lib)
install(TARGETS aigis_cert_tool RUNTIME DESTINATION bin)
install(FILES include/aigis_cert.h DESTINATION include)
