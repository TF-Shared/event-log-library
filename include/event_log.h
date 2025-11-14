/*
 * Copyright (c) 2020-2025, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef EVENT_LOG_H
#define EVENT_LOG_H

#include <stddef.h>
#include <stdint.h>

#include "sha_common_macros.h"
/* Shared sizing macros are defined in event_log_def.h for C/asm consumers. */
#include "event_log_def.h"
#include <tcg.h>

/* Maximum digest size based on the strongest hash algorithm i.e. SHA-512. */
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE SHA512_DIGEST_SIZE
#endif /* !MAX_DIGEST_SIZE */

#define MAX_TPML_BUFFER_SIZE          \
	(sizeof(tpml_digest_values) + \
	 (HASH_ALG_COUNT * (sizeof(tpmt_ha) + MAX_DIGEST_SIZE)))

#define MEMBER_SIZE(type, member) sizeof(((type *)0)->member)

struct event_log_algorithm {
	uint16_t id;
	const char *name;
	uint16_t size;
};

typedef struct event_log_metadata {
	unsigned int id;
	const char *name;
	unsigned int pcr;
} event_log_metadata_t;

#define ID_EVENT_SIZE                                                \
	(sizeof(tcg_pcr_event_t) + sizeof(tcg_efi_spec_id_event_t) + \
	 (sizeof(id_event_algorithm_size_t) * HASH_ALG_COUNT) +      \
	 sizeof(tcg_vendor_info_t))

#define LOC_EVENT_SIZE                                            \
	(sizeof(event2_header_t) +                                \
	 (HASH_ALG_COUNT * (sizeof(tpmt_ha) + MAX_DIGEST_SIZE)) + \
	 sizeof(event2_data_t) + sizeof(startup_locality_event_t))

#endif /* EVENT_LOG_H */
