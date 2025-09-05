/*
 * Copyright (c) 2025, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef EVENT_RECORD_H
#define EVENT_RECORD_H

#include "event_log.h"

/* Functions' declarations */

/**
 * Initialize the Event Log buffer.
 *
 * Sets global pointers to manage the Event Log memory region,
 * allowing subsequent log operations to write into the buffer.
 *
 * @param[in] start  Pointer to the start of the Event Log buffer.
 * @param[in] finish Pointer to the end of the buffer
 *                             (i.e., one byte past the last valid address).
 *
 * @return 0 on success, or -EINVAL if the input range is invalid.
 */
int event_log_buf_init(uint8_t *start, uint8_t *finish);

/**
 * Initialize the Event Log subsystem.
 *
 * Wrapper around `event_log_buf_init()` to configure the memory range
 * for the Event Log buffer.
 *
 * @param[in] start  Pointer to the start of the Event Log buffer.
 * @param[in] finish Pointer to the end of the buffer
 *                             (i.e., one byte past the last valid address).
 *
 * @return 0 on success, or a negative error code on failure.
 */
int event_log_init(uint8_t *start, uint8_t *finish);

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
 * @param[in] hash_info  Pointer to a structure containing the hash function
 *                       pointer and associated algorithm identifiers.
 *
 * @return 0 on success,
 *         -EEXIST if hash functions have already been registered,
 *         -EINVAL if the input parameters are invalid,
 *         or a negative error code from the underlying initialization logic.
 */
int event_log_init_and_reg(uint8_t *start, uint8_t *finish,
			   const struct event_log_hash_info *hash_info);

/**
 * Record a measurement event in the Event Log.
 *
 * Writes a TCG_PCR_EVENT2 structure to the Event Log using the
 * provided hash and metadata. This function assumes the buffer
 * has enough space and that `event_log_buf_init()` has been called.
 *
 * @param[in] hash         Pointer to the digest (TCG_DIGEST_SIZE bytes).
 * @param[in] event_type   Type of the event, as defined in tcg.h.
 * @param[in] metadata_ptr Pointer to an event_log_metadata_t structure
 *                         providing event-specific context (e.g., PCR index, name).
 *
 * @return 0 on success, or -ENOMEM if the buffer has insufficient space.
 */
int event_log_record(const uint8_t *hash, uint32_t event_type,
		     const event_log_metadata_t *metadata_ptr);

/**
 * @brief Write a PCR event with multiple digests.
 *
 * @param[in] pcr_index        PCR index of the event.
 * @param[in] event_type       Type of the event.
 * @param[in] digests          Pointer to digest values.
 * @param[in] event_data       Pointer to event data.
 * @param[in] event_data_size  Size of event data in bytes.
 *
 * @return 0 on success, negative on error.
 *
  * @note In the PC Client spec for TPM 1.2, the event log used a fixed SHA-1 digest
 *       (20 bytes) for each event (SHA1 log format). With TPM 2.0, PCRs may use
 *       multiple hash algorithms, so each event must include all digests recorded
 *       (crypto-agile event log format).
 *
 */

int event_log_write_pcr_event2(uint32_t pcr_index, uint32_t event_type,
			       const tpml_digest_values *digests,
			       const uint8_t *event_data,
			       uint32_t event_data_size);

/**
 * @brief Write a PCR event with a single digest.
 *
 * @param[in] pcr_index        PCR index of the event.
 * @param[in] event_type       Type of the event.
 * @param[in] algorithm_id     Hash function ID.
 * @param[in] digest           Pointer to digest values.
 * @param[in] event_data       Pointer to event data.
 * @param[in] event_data_size  Size of event data in bytes.
 *
 * @return 0 on success, negative on error.
 *
 */
int event_log_write_pcr_event2_single(uint32_t pcr_index, uint32_t event_type,
				      uint32_t algorithm_id, uint8_t *digest,
				      const uint8_t *event_data,
				      uint32_t event_data_size);

/**
 * Initialize the Event Log with mandatory header events.
 *
 * Writes the Specification ID (SpecID) and Startup Locality events
 * as required by the TCG PC Client Platform Firmware Profile.
 * These must be the first entries in the Event Log.
 *
 * @return 0 on success, or a negative error code on failure.
 */
int event_log_write_header(void);

/**
 * Write the SpecID event to the Event Log.
 *
 * Records the TCG_EfiSpecIDEventStruct to declare the structure
 * and supported algorithms of the Event Log format.
 *
 * @return 0 on success, or a negative error code on failure.
 */
int event_log_write_specid_event(void);

/**
 * Get the current size of the Event Log.
 *
 * Calculates how many bytes of the Event Log buffer have been used,
 * based on the current log pointer and the start of the buffer.
 *
 * @param[in] start Pointer to the start of the Event Log buffer.
 *
 * @return The number of bytes currently used in the Event Log.
 */
size_t event_log_get_cur_size(uint8_t *start);

#endif
