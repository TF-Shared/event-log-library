/*
 * Copyright (c) 2025-2026, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef EVENT_LOG_DEF_H
#define EVENT_LOG_DEF_H

#include <event_log_config_def.h>

/* sizeof() structures cannot be used here, so hard-code values derived
 * from the packed structure layouts and assert them in C code.
 */
#ifndef HASH_ALG_COUNT
#ifndef MAX_HASH_COUNT
#define HASH_ALG_COUNT 1
#else
#define HASH_ALG_COUNT MAX_HASH_COUNT
#endif /* !MAX_HASH_COUNT */
#endif /* !HASH_ALG_COUNT */

#if (HASH_ALG_COUNT == 1)
#define EVENT2_HDR_SIZE (18 + MAX_DIGEST_SIZE)
#define LOG_MIN_SIZE (100 + MAX_DIGEST_SIZE)
#else
#define EVENT2_HDR_SIZE (16 + (HASH_ALG_COUNT * (2 + MAX_DIGEST_SIZE)))
#define LOG_MIN_SIZE \
	(94 + (4 * HASH_ALG_COUNT) + (HASH_ALG_COUNT * (2 + MAX_DIGEST_SIZE)))
#endif

#endif /* EVENT_LOG_DEF_H */
