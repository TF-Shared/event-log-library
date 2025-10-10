/*
 * Copyright (c) 2025, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef EVENT_MEASURE_H
#define EVENT_MEASURE_H

#include "event_log.h"
#include "event_record.h"

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

/**
 * Initialize the Event Log and register supported hash functions.
 *
 * Initializes the Event Log subsystem using the provided memory region
 * and registers one or more cryptographic hash functions for use in
 * event measurements. This function must be called before any measurements
 * or event recording can take place.
 *
 * @param[in] start      Pointer to the beginning of the Event Log buffer.
 * @param[in] finish     Pointer to the end of the Event Log buffer.
 * @param[in] pos        Previous cursor position.
 * @param[in] hash_info  Pointer to a structure containing the hash function
 *                       pointer and associated algorithm identifiers.
 *
 * @return 0 on success,
 *         -EEXIST if hash functions have already been registered,
 *
 * -EINVAL if the input parameters are invalid,
 * or a negative error code from the underlying initialization logic.
 */
int event_log_init_and_reg(uint8_t *start, uint8_t *finish, size_t pos,
			   const struct event_log_hash_info *hash_info);

/**
 * Measure input data and log its hash to the Event Log.
 *
 * Computes the cryptographic hash of the specified data and records it
 * in the Event Log as a TCG_PCR_EVENT2 structure using event type EV_POST_CODE.
 * Useful for firmware or image attestation.
 *
 * @param[in] data_base     Pointer to the base of the data to be measured.
 * @param[in] data_size     Size of the data in bytes.
 * @param[in] data_id       Identifier used to match against metadata.
 * @param[in] metadata_ptr  Pointer to an array of event_log_metadata_t.
 *
 * @return 0 on success, or a negative error code on failure.
 */
int event_log_measure_and_record(uintptr_t data_base, uint32_t data_size,
				 uint32_t data_id,
				 const event_log_metadata_t *metadata_ptr);

/**
 * Measure the input data and return its hash.
 *
 * Computes the cryptographic hash of the specified memory region using
 * the default hashing algorithm configured in the Event Log subsystem.
 *
 * @param[in]  data_base  Pointer to the base of the data to be measured.
 * @param[in]  data_size  Size of the data in bytes.
 * @param[out] hash_data  Buffer to hold the resulting hash output
 *                        (must be at least CRYPTO_MD_MAX_SIZE bytes).
 *
 * @return 0 on success, or an error code on failure.
 */
int event_log_measure(uintptr_t data_base, uint32_t data_size,
		      unsigned char *hash_data);

#endif /* EVENT_MEASURE_H */
