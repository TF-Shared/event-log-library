/*
 * Copyright (c) 2020-2025, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include "debug.h"
#include "event_log.h"
#include "event_record.h"

/* Running Event Log Pointer */
static uint8_t *log_ptr;

/* Pointer to the first byte past end of the Event Log buffer */
static uintptr_t log_end;

/* Hash function for event log operations set by user. */
static const struct event_log_hash_info *crypto_hash_info;

static const tcg_efi_spec_id_event_t *spec_id_header;

/* TCG_EfiSpecIdEvent */
static const id_event_headers_t id_event_header = {
	.header = { .pcr_index = PCR_0,
		    .event_type = EV_NO_ACTION,
		    .digest = { 0 },
		    .event_size =
			    (uint32_t)(sizeof(id_event_struct_t) +
				       (sizeof(id_event_algorithm_size_t) *
					HASH_ALG_COUNT)) },

	.struct_header = { .signature = TCG_ID_EVENT_SIGNATURE_03,
			   .platform_class = PLATFORM_CLASS_CLIENT,
			   .spec_version_minor = TCG_SPEC_VERSION_MINOR_TPM2,
			   .spec_version_major = TCG_SPEC_VERSION_MAJOR_TPM2,
			   .spec_errata = TCG_SPEC_ERRATA_TPM2,
			   .uintn_size = (uint8_t)(sizeof(unsigned int) /
						   sizeof(uint32_t)),
			   .number_of_algorithms = HASH_ALG_COUNT }
};

static const event2_header_t locality_event_header = {
	/*
	 * All EV_NO_ACTION events SHALL set
	 * TCG_PCR_EVENT2.pcrIndex = 0, unless otherwise specified
	 */
	.pcr_index = PCR_0,

	/*
	 * All EV_NO_ACTION events SHALL set
	 * TCG_PCR_EVENT2.eventType = 03h
	 */
	.event_type = EV_NO_ACTION,

	/*
	 * All EV_NO_ACTION events SHALL set TCG_PCR_EVENT2.digests to all
	 * 0x00's for each allocated Hash algorithm
	 */
	.digests = { .count = HASH_ALG_COUNT }
};

/* Message digest algorithm */
enum crypto_md_algo {
	CRYPTO_MD_SHA256,
	CRYPTO_MD_SHA384,
	CRYPTO_MD_SHA512,
};

/* size lookup from your spec_id_header table */
static inline uint16_t digest_size_for_alg(uint16_t alg)
{
	assert(spec_id_header != NULL);

	for (size_t k = 0U; k < spec_id_header->number_of_algorithms; k++) {
		if (spec_id_header->digest_size[k].algorithm_id == alg) {
			return spec_id_header->digest_size[k].digest_size;
		}
	}

	return 0;
}

static inline bool exceeds_bounds(uintptr_t ptr, size_t min_size)
{
	return min_size > log_end - ptr;
}

int event_log_record(const uint8_t *hash, uint32_t event_type,
		     const event_log_metadata_t *metadata_ptr)
{
	void *ptr = log_ptr;
	uint32_t name_len = 0U;

	/* event_log_buf_init() must have been called prior to this. */
	if (hash == NULL || metadata_ptr == NULL || log_ptr == NULL) {
		return -EINVAL;
	}

	if (metadata_ptr->name != NULL) {
		name_len = (uint32_t)strlen(metadata_ptr->name) + 1U;
	}

	/* Check for space in Event Log buffer */
	if (((uintptr_t)ptr + (uint32_t)EVENT2_HDR_SIZE + name_len) > log_end) {
		return -ENOMEM;
	}

	/*
	 * As per TCG specifications, firmware components that are measured
	 * into PCR[0] must be logged in the event log using the event type
	 * EV_POST_CODE.
	 */
	/* TCG_PCR_EVENT2.PCRIndex */
	((event2_header_t *)ptr)->pcr_index = metadata_ptr->pcr;

	/* TCG_PCR_EVENT2.EventType */
	((event2_header_t *)ptr)->event_type = event_type;

	/* TCG_PCR_EVENT2.Digests.Count */
	ptr = (uint8_t *)ptr + offsetof(event2_header_t, digests);
	((tpml_digest_values *)ptr)->count = HASH_ALG_COUNT;

	/* TCG_PCR_EVENT2.Digests[] */
	ptr = (uint8_t *)((uintptr_t)ptr +
			  offsetof(tpml_digest_values, digests));

	/* TCG_PCR_EVENT2.Digests[].AlgorithmId */
	((tpmt_ha *)ptr)->algorithm_id = TPM_ALG_ID;

	/* TCG_PCR_EVENT2.Digests[].Digest[] */
	ptr = (uint8_t *)((uintptr_t)ptr + offsetof(tpmt_ha, digest));

	/* Copy digest */
	(void)memcpy(ptr, (const void *)hash, TCG_DIGEST_SIZE);

	/* TCG_PCR_EVENT2.EventSize */
	ptr = (uint8_t *)((uintptr_t)ptr + TCG_DIGEST_SIZE);
	((event2_data_t *)ptr)->event_size = name_len;

	/* Copy event data to TCG_PCR_EVENT2.Event */
	if (metadata_ptr->name != NULL) {
		(void)memcpy((void *)(((event2_data_t *)ptr)->event),
			     (const void *)metadata_ptr->name, name_len);
	}

	/* End of event data */
	log_ptr = (uint8_t *)((uintptr_t)ptr + offsetof(event2_data_t, event) +
			      name_len);

	return 0;
}

int event_log_write_pcr_event2_single(uint32_t pcr_index, uint32_t event_type,
				      uint32_t algorithm_id, uint8_t *digest,
				      const uint8_t *event_data,
				      uint32_t event_data_size)
{
	uint8_t *dst_p;
	event2_header_t *pcr_event = (event2_header_t *)log_ptr;
	uint16_t digest_size;

	if (log_ptr == NULL || spec_id_header == NULL) {
		ERROR("Cannot call library function, initialization not completed.\n");
		return -EFAULT;
	}

	if (event_type != EV_NO_ACTION && digest == NULL) {
		return -EINVAL;
	}

	if (event_data_size > 0U && event_data == NULL) {
		return -EINVAL;
	}

	/* Minimum space: header without digests/data */
	if (exceeds_bounds((uintptr_t)pcr_event, sizeof(event2_header_t))) {
		return -ENOMEM;
	}

	pcr_event->pcr_index = pcr_index;
	pcr_event->event_type = event_type;

	/* TCG_PCR_EVENT2.Digests.Count */
	if (spec_id_header->number_of_algorithms != 1U ||
	    algorithm_id != spec_id_header->digest_size[0].algorithm_id) {
		/*
		 * Only write single digests when only one algorithm is registered, each
		 * entry should have as many digests as are registered in the SpecID
		 * event.
		 */
		return -EINVAL;
	}

	pcr_event->digests.count = spec_id_header->number_of_algorithms;

	/* TCG_PCR_EVENT2.Digests.Digests[] */
	pcr_event->digests.digests->algorithm_id = algorithm_id;
	digest_size = digest_size_for_alg(algorithm_id);
	if (digest_size == 0U) {
		return -EINVAL;
	}

	(void)memcpy(pcr_event->digests.digests[0].digest, digest, digest_size);

	dst_p = pcr_event->digests.digests[0].digest + digest_size;

	if (exceeds_bounds((uintptr_t)dst_p,
			   sizeof(event_data) + event_data_size)) {
		return -ENOMEM;
	}

	((event2_data_t *)dst_p)->event_size = event_data_size;
	dst_p += offsetof(event2_data_t, event);

	if (event_data_size > 0U) {
		(void)memcpy(dst_p, event_data, event_data_size);
		dst_p += event_data_size;
	}

	log_ptr = dst_p;

	return 0;
}

int event_log_write_pcr_event2(uint32_t pcr_index, uint32_t event_type,
			       const tpml_digest_values *digests,
			       const uint8_t *event_data,
			       uint32_t event_data_size)
{
	size_t tpmt_ha_digest_sz;
	uint8_t *dst_p;
	tpmt_ha *curr = NULL;
	event2_header_t *pcr_event = (event2_header_t *)log_ptr;
	uint16_t digest_size;

	if (log_ptr == NULL || spec_id_header == NULL) {
		ERROR("Cannot call library function, initialization not completed.\n");
		return -EFAULT;
	}

	if (event_type != EV_NO_ACTION) {
		if (digests == NULL || digests->count == 0 ||
		    digests->count != spec_id_header->number_of_algorithms) {
			ERROR("Invalid digests, none passed or mismatch with SpecID Header.\n");
			return -EINVAL;
		}

		curr = (tpmt_ha *)&digests->digests;
	}

	if (event_data_size > 0U && event_data == NULL) {
		return -EINVAL;
	}

	/* Minimum space: header without digests/data */
	if (exceeds_bounds((uintptr_t)pcr_event, sizeof(event2_header_t))) {
		return -ENOMEM;
	}

	pcr_event->pcr_index = pcr_index;
	pcr_event->event_type = event_type;

	/* TCG_PCR_EVENT2.Digests.Count */
	pcr_event->digests.count = spec_id_header->number_of_algorithms;

	/* TCG_PCR_EVENT2.Digests.Digests[] */
	dst_p = (uint8_t *)&pcr_event->digests.digests;

	for (size_t i = 0; i < spec_id_header->number_of_algorithms; i++) {
		if (pcr_event->event_type == EV_NO_ACTION) {
			((tpmt_ha *)dst_p)->algorithm_id =
				spec_id_header->digest_size[i].algorithm_id;

			(void)memset(
				((tpmt_ha *)dst_p)->digest, 0,
				spec_id_header->digest_size[i].digest_size);

			dst_p += sizeof(tpmt_ha) +
				 spec_id_header->digest_size[i].digest_size;
		} else {
			digest_size = digest_size_for_alg(curr->algorithm_id);

			tpmt_ha_digest_sz = sizeof(tpmt_ha) + digest_size;

			if (exceeds_bounds((uintptr_t)dst_p,
					   tpmt_ha_digest_sz)) {
				return -ENOMEM;
			}

			/* TCG_PCR_EVENT2.Digests.Digests[i] */
			(void)memcpy(dst_p, curr, tpmt_ha_digest_sz);

			/* Increment to next digest location accounting for variable length digests. */
			curr = (tpmt_ha *)((uint8_t *)curr + digest_size);
			dst_p += tpmt_ha_digest_sz;
		}
	}

	if (exceeds_bounds((uintptr_t)dst_p,
			   sizeof(event_data) + event_data_size)) {
		return -ENOMEM;
	}

	((event2_data_t *)dst_p)->event_size = event_data_size;
	dst_p += offsetof(event2_data_t, event);

	if (event_data_size > 0U) {
		(void)memcpy(dst_p, event_data, event_data_size);
		dst_p += event_data_size;
	}

	log_ptr = dst_p;

	return 0;
}

int event_log_init(uint8_t *start, uint8_t *finish)
{
	if ((start == NULL || finish == NULL) || start > finish) {
		return -EINVAL;
	}

	log_ptr = start;
	log_end = (uintptr_t)finish;

	return 0;
}

int event_log_write_specid_event(void)
{
	void *ptr;

	/* event_log_buf_init() must have been called prior to this. */
	if (log_ptr == NULL) {
		return -EFAULT;
	}

	if (((uintptr_t)log_ptr + ID_EVENT_SIZE) > log_end) {
		return -ENOMEM;
	}

	ptr = log_ptr;

	/*
	 * Add Specification ID Event first
	 *
	 * Copy TCG_EfiSpecIDEventStruct structure header
	 */
	(void)memcpy(ptr, (const void *)&id_event_header,
		     sizeof(id_event_header));
	ptr = (uint8_t *)((uintptr_t)ptr + sizeof(id_event_header));

	/* TCG_EfiSpecIdEventAlgorithmSize structure */
	((id_event_algorithm_size_t *)ptr)->algorithm_id = TPM_ALG_ID;
	((id_event_algorithm_size_t *)ptr)->digest_size = TCG_DIGEST_SIZE;
	ptr = (uint8_t *)((uintptr_t)ptr + sizeof(id_event_algorithm_size_t));

	/*
	 * TCG_EfiSpecIDEventStruct.vendorInfoSize
	 * No vendor data
	 */
	((tcg_vendor_info_t *)ptr)->vendor_info_size = 0;
	log_ptr = (uint8_t *)((uintptr_t)ptr +
			      offsetof(tcg_vendor_info_t, vendor_info));

	return 0;
}

int event_log_write_header(void)
{
	const char locality_signature[] = TCG_STARTUP_LOCALITY_SIGNATURE;
	void *ptr;
	int rc;

	rc = event_log_write_specid_event();
	if (rc < 0) {
		return rc;
	}

	if (((uintptr_t)log_ptr + LOC_EVENT_SIZE) > log_end) {
		return -ENOMEM;
	}

	ptr = log_ptr;

	/*
	 * The Startup Locality event should be placed in the log before
	 * any event which extends PCR[0].
	 *
	 * Ref. TCG PC Client Platform Firmware Profile 9.4.5.3
	 */

	/* Copy Startup Locality Event Header */
	(void)memcpy(ptr, (const void *)&locality_event_header,
		     sizeof(locality_event_header));
	ptr = (uint8_t *)((uintptr_t)ptr + sizeof(locality_event_header));

	/* TCG_PCR_EVENT2.Digests[].AlgorithmId */
	((tpmt_ha *)ptr)->algorithm_id = TPM_ALG_ID;

	/* TCG_PCR_EVENT2.Digests[].Digest[] */
	(void)memset(&((tpmt_ha *)ptr)->digest, 0, TCG_DIGEST_SIZE);
	ptr = (uint8_t *)((uintptr_t)ptr + offsetof(tpmt_ha, digest) +
			  TCG_DIGEST_SIZE);

	/* TCG_PCR_EVENT2.EventSize */
	((event2_data_t *)ptr)->event_size =
		(uint32_t)sizeof(startup_locality_event_t);
	ptr = (uint8_t *)((uintptr_t)ptr + offsetof(event2_data_t, event));

	/* TCG_EfiStartupLocalityEvent.Signature */
	(void)memcpy(ptr, (const void *)locality_signature,
		     sizeof(TCG_STARTUP_LOCALITY_SIGNATURE));

	/*
	 * TCG_EfiStartupLocalityEvent.StartupLocality = 0:
	 * the platform's boot firmware
	 */
	((startup_locality_event_t *)ptr)->startup_locality = 0U;
	log_ptr =
		(uint8_t *)((uintptr_t)ptr + sizeof(startup_locality_event_t));

	return 0;
}

int event_log_measure(uintptr_t data_base, uint32_t data_size,
		      unsigned char *hash_data)
{
	if (crypto_hash_info == NULL) {
		return -EINVAL;
	}

	return crypto_hash_info->func(crypto_hash_info->ids[0],
				      (void *)data_base, data_size, hash_data);
}

int event_log_init_and_reg(uint8_t *start, uint8_t *finish,
			   const struct event_log_hash_info *hash_info)
{
	int rc = event_log_init(start, finish);
	if (rc < 0) {
		return rc;
	}

	if (hash_info == NULL || hash_info->func == NULL ||
	    hash_info->count == 0U || hash_info->count > HASH_ALG_COUNT) {
		return -EINVAL;
	}

	crypto_hash_info = hash_info;
	return 0;
}

int event_log_measure_and_record(uintptr_t data_base, uint32_t data_size,
				 uint32_t data_id,
				 const event_log_metadata_t *metadata_ptr)
{
	unsigned char hash_data[MAX_DIGEST_SIZE];
	int rc;

	if (metadata_ptr == NULL) {
		return -EINVAL;
	}

	/* Get the metadata associated with this image. */
	while (metadata_ptr->id != data_id) {
		if (metadata_ptr->id == EVLOG_INVALID_ID) {
			return -EINVAL;
		}

		metadata_ptr++;
	}

	/* Measure the payload with algorithm selected by EventLog driver */
	rc = event_log_measure(data_base, data_size, hash_data);
	if (rc != 0) {
		return rc;
	}

	rc = event_log_record(hash_data, EV_POST_CODE, metadata_ptr);
	if (rc != 0) {
		return rc;
	}

	return 0;
}

size_t event_log_get_cur_size(uint8_t *_start)
{
	assert(_start != NULL);
	assert(log_ptr >= _start);

	return (size_t)((uintptr_t)log_ptr - (uintptr_t)_start);
}
