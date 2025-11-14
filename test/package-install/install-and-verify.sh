#!/usr/bin/env bash
#
# Copyright (c) 2025, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_INSTALL_DIR="${SCRIPT_DIR}"

LIBEVENTLOG_DIR="$(realpath "${SCRIPT_DIR}/../..")"

build_variant() {
	local name="$1"
	local max_hash="$2"
	local max_digest="$3"
	local install_dir
	local lib_build_dir
	local test_build_dir

	lib_build_dir="${LIBEVENTLOG_DIR}/build-${name}"
	test_build_dir="${TEST_INSTALL_DIR}/build-${name}"
	install_dir="$(mktemp -d)"

	echo "==> Building main project (${name}) at ${LIBEVENTLOG_DIR}"
	cmake -S "${LIBEVENTLOG_DIR}" -B "${lib_build_dir}" \
		-DCMAKE_INSTALL_PREFIX="${install_dir}" \
		-DDEBUG_BACKEND_HEADER="log_backend_printf.h" \
		-DMAX_HASH_COUNT="${max_hash}" \
		-DMAX_DIGEST_SIZE="${max_digest}" \
		--fresh
	cmake --build "${lib_build_dir}" --parallel
	cmake --install "${lib_build_dir}"

	find "${install_dir}" -maxdepth 5 -type f \( \
	  -name "*Config.cmake" -o -name "*-config.cmake" -o -name "*Targets.cmake" \) -print

	echo "==> Building subproject (${name}) at ${TEST_INSTALL_DIR}"
	cmake -S "${TEST_INSTALL_DIR}" -B "${test_build_dir}" \
		-DCMAKE_PREFIX_PATH="${install_dir}" \
		-DCMAKE_C_FLAGS="-DMAX_HASH_COUNT=${max_hash} -DMAX_DIGEST_SIZE=${max_digest}" \
		--fresh
	cmake --build "${test_build_dir}" --parallel

	echo "==> Building subproject (${name}) at ${TEST_INSTALL_DIR} without CMake"
	cc -DMAX_HASH_COUNT="${max_hash}" -DMAX_DIGEST_SIZE="${max_digest}" \
		-I"${install_dir}/include" -L"${install_dir}/lib" \
		"${TEST_INSTALL_DIR}/main.c" -leventlog -o test-${name}
}

build_variant "single" 1 32
build_variant "multi" 3 64
