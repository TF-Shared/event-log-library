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

SET(TARGET_GROUP release CACHE STRING "Specify the Build Target [\"release\" by default]")

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
)

target_include_directories(eventlog PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(eventlog PUBLIC cxx_compiler_flags)
