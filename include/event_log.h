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

#endif /* EVENT_LOG_H */
