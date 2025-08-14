/*
 * Copyright (c) 2020-2025, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef EVENT_LOG_H
#define EVENT_LOG_H

#include <stddef.h>
#include <stdint.h>

#include <tcg.h>

/* Number of hashing algorithms supported */
#define HASH_ALG_COUNT 1U

#define EVLOG_INVALID_ID UINT32_MAX

/* Maximum digest size based on the strongest hash algorithm i.e. SHA-512. */
#define MAX_DIGEST_SIZE 64U

#define MEMBER_SIZE(type, member) sizeof(((type *)0)->member)

typedef struct {
	unsigned int id;
	const char *name;
	unsigned int pcr;
} event_log_metadata_t;

typedef int (*evlog_hash_func_t)(uint32_t alg, void *data, unsigned int len,
				 uint8_t *digest);

struct event_log_hash_info {
	evlog_hash_func_t func;
	const uint32_t *ids;
	size_t count;
};

struct event_log_algorithm {
	uint16_t id;
	const char *name;
	uint16_t size;
};

#define ID_EVENT_SIZE                                           \
	(sizeof(id_event_headers_t) +                           \
	 (sizeof(id_event_algorithm_size_t) * HASH_ALG_COUNT) + \
	 sizeof(id_event_struct_data_t))

#define LOC_EVENT_SIZE                                                 \
	(sizeof(event2_header_t) + sizeof(tpmt_ha) + TCG_DIGEST_SIZE + \
	 sizeof(event2_data_t) + sizeof(startup_locality_event_t))

#define LOG_MIN_SIZE (ID_EVENT_SIZE + LOC_EVENT_SIZE)

#define EVENT2_HDR_SIZE                                                \
	(sizeof(event2_header_t) + sizeof(tpmt_ha) + TCG_DIGEST_SIZE + \
	 sizeof(event2_data_t))

#endif /* EVENT_LOG_H */
