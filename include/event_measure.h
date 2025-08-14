/*
 * Copyright (c) 2025, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef EVENT_MEASURE_H
#define EVENT_MEASURE_H

#include "event_log.h"
#include "event_record.h"

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
