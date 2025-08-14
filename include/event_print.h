/*
 * Copyright (c) 2025, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef EVENT_PRINT_H
#define EVENT_PRINT_H

#include <stdint.h>

/**
 * Dump the contents of the Event Log.
 *
 * Outputs the raw contents of the Event Log buffer, typically
 * for debugging or audit purposes.
 *
 * @param[in] log_addr Pointer to the start of the Event Log buffer.
 * @param[in] log_size Size of the Event Log buffer in bytes.
 *
 * @return 0 on success, or a negative error code on failure.
 */
int event_log_dump(uint8_t *log_addr, size_t log_size);

#endif
