#
# Copyright (c) 2025, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

cmake_minimum_required(VERSION 3.15)

project(libeventlog VERSION 0.9 LANGUAGES C CXX ASM)
set(CMAKE_C_STANDARD_REQUIRED TRUE)
set(CMAKE_C_EXTENSIONS TRUE)

add_library(cxx_compiler_flags INTERFACE)
target_compile_features(cxx_compiler_flags INTERFACE cxx_std_11)

set(
    LOG_LEVEL "" CACHE STRING
    "Log Level options:
     0  - NONE
     10 - ERROR
     20 - NOTICE
     30 - WARNING
     40 - INFO
     50 - VERBOSE"
)

if(LOG_LEVEL STREQUAL "")
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        set(LOG_LEVEL 20)
    else()
        set(LOG_LEVEL 40)
    endif()
endif()

add_compile_definitions(EVLOG_LOG_LEVEL=${LOG_LEVEL})

set(DEBUG_BACKEND_HEADER "log_backend_tf.h" CACHE STRING "Path to debug backend header")
add_compile_definitions(DEBUG_BACKEND_HEADER="${DEBUG_BACKEND_HEADER}")

if(HASH_ALGORITHM STREQUAL "SHA512")
    add_compile_definitions(TPM_ALG_ID=TPM_ALG_SHA512)
    add_compile_definitions(TCG_DIGEST_SIZE=64U)
elseif(HASH_ALGORITHM STREQUAL "SHA384")
    add_compile_definitions(TPM_ALG_ID=TPM_ALG_SHA384)
    add_compile_definitions(TCG_DIGEST_SIZE=48U)
else()
    add_compile_definitions(TPM_ALG_ID=TPM_ALG_SHA256)
    add_compile_definitions(TCG_DIGEST_SIZE=32U)
endif()

add_library(eventlog STATIC
    ${PROJECT_SOURCE_DIR}/src/event_log.c
    ${PROJECT_SOURCE_DIR}/src/event_print.c
    ${PROJECT_SOURCE_DIR}/src/digest.c
)

target_include_directories(eventlog PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_include_directories(eventlog PRIVATE ${CMAKE_SOURCE_DIR}/include/private)

target_link_libraries(eventlog PUBLIC
    $<BUILD_INTERFACE:cxx_compiler_flags>
)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS eventlog
    EXPORT eventLogTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    PATTERN "private" EXCLUDE
)

install(EXPORT eventLogTargets
    FILE eventLogTargets.cmake
    NAMESPACE eventlog::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/eventlog
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/eventLogConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    "${PROJECT_SOURCE_DIR}/cmake/eventLogConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/eventLogConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/eventlog
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/eventLogConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/eventLogConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/eventlog
)
