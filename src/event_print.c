/*
 * Copyright (c) 2020-2025, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include "debug.h"
#include "digest.h"
#include "event_log.h"
#include "event_print.h"

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Pretty-print a digest as 16-byte spaced hex rows with a
 * header/continuation prefix.
 *
 * Emits one or more lines through the NOTICE() logging macro.
 * Each line renders up to 16 bytes as "aa bb …".
 *
 * @param[in] buf         Byte array to print.
 * @param[in] buf_len     Number of bytes in @p digest.
 * @param[in] prefix      Prefix to append to the byte array (e.g. 'VendorInfo      :').
 *
 */
static void event_log_print_spaced_hex(const uint8_t *buf, size_t buf_len,
				       const char *prefix)
{
	char output_buf[256];
	const size_t cap = sizeof(output_buf);
	size_t pos = 0U;
	size_t chunk;
	size_t free;
	size_t space_width;
	char cont[128];

	if (buf == NULL || buf_len == 0U) {
		return;
	}

	/* Start from just after the prefix */
	event_log_append_str(output_buf, cap, &pos, prefix);
	event_log_append_str(output_buf, cap, &pos, ": ");

	/* width of spaces before ':' in the continuation line */
	space_width = (pos >= 2) ? (pos - 2) : 0U;
	if (space_width > sizeof(cont) - 3U) {
		space_width = sizeof(cont) - 3U;
	}

	memset(cont, ' ', space_width);
	cont[space_width] = ':';
	cont[space_width + 1] = ' ';
	cont[space_width + 2] = '\0';

	for (size_t off = 0U; off < buf_len; off += 16U) {
		chunk = (buf_len - off >= 16U) ? 16U : (buf_len - off);
		free = (pos < cap) ? cap - pos : 0U;

		if (free == 0U) {
			/* buffer full — print what we have (after forcing NUL) and restart line */
			output_buf[cap - 1] = '\0';
			NOTICE("  %s\n", output_buf);

			pos = 0U;
			output_buf[0] = '\0';
			event_log_append_str(output_buf, cap, &pos, cont);
			free = cap - pos;
		}

		/* write the 16-byte (or tail) chunk */
		pos += event_log_write_hex_spaced(output_buf + pos, free, chunk,
						  buf + off);

		NOTICE("  %s\n", output_buf);

		/* prepare next line: reset to prefix only */
		pos = 0U;
		output_buf[0] = '\0';
		event_log_append_str(output_buf, cap, &pos, cont);
	}
}

static void event_log_print_digest(const uint8_t *digest, size_t digest_len)
{
	/*
	 * Add extra padding at the start of the digest so it's nested under its
	 * respective AlgorithmID.
	 */
	event_log_print_spaced_hex(digest, digest_len, "     Digest        ");
}

/**
 * Print a TCG_EfiSpecIDEventStruct entry from the event log.
 *
 * This function extracts and prints a TCG_EfiSpecIDEventStruct
 * entry from the event log for debugging or auditing purposes.
 *
 * @param[in,out] log_addr  Pointer to the current position in the Event Log.
 *                          Updated to the next entry after processing.
 * @param[in,out] log_size  Pointer to the remaining Event Log size.
 *                          Updated to reflect the remaining bytes.
 *
 * @return 0 on success, or a negative error code on failure.
 */
static int event_log_print_id_event(uint8_t **log_addr, size_t *log_size)
{
	unsigned int i;
	uint8_t info_size, *info_size_ptr;
	void *ptr = *log_addr;
	id_event_headers_t *event = (id_event_headers_t *)ptr;
	id_event_algorithm_size_t *alg_ptr;
	uint32_t event_size, number_of_algorithms;
	size_t digest_len;
	const uint8_t *end_ptr = (uint8_t *)((uintptr_t)*log_addr + *log_size);
	const struct event_log_algorithm *algo_info;

	if (*log_size < sizeof(id_event_headers_t)) {
		return -EINVAL;
	}

	/* The fields of the event log header are defined to be PCRIndex of 0,
	 * EventType of EV_NO_ACTION, Digest of 20 bytes of 0, and
	 * Event content defined as TCG_EfiSpecIDEventStruct.
	 */
	NOTICE("TCG_EfiSpecIDEvent:\n");
	NOTICE("  PCRIndex           : %u\n", event->header.pcr_index);
	if (event->header.pcr_index != (uint32_t)PCR_0) {
		return -EINVAL;
	}

	NOTICE("  EventType          : %u\n", event->header.event_type);
	if (event->header.event_type != EV_NO_ACTION) {
		return -EINVAL;
	}

	event_log_print_digest(event->header.digest,
			       sizeof(event->header.digest));

	/* EventSize */
	event_size = event->header.event_size;
	NOTICE("  EventSize          : %u\n", event_size);

	NOTICE("  Signature          : %s\n", event->struct_header.signature);
	NOTICE("  PlatformClass      : %u\n",
	       event->struct_header.platform_class);
	NOTICE("  SpecVersion        : %u.%u.%u\n",
	       event->struct_header.spec_version_major,
	       event->struct_header.spec_version_minor,
	       event->struct_header.spec_errata);
	NOTICE("  UintnSize          : %u\n", event->struct_header.uintn_size);

	/* NumberOfAlgorithms */
	number_of_algorithms = event->struct_header.number_of_algorithms;
	NOTICE("  NumberOfAlgorithms : %u\n", number_of_algorithms);

	/* Address of DigestSizes[] */
	alg_ptr = event->struct_header.digest_size;

	/* Size of DigestSizes[] */
	digest_len = number_of_algorithms * sizeof(id_event_algorithm_size_t);
	if (digest_len > (uintptr_t)end_ptr - (uintptr_t)alg_ptr) {
		return -EFAULT;
	}

	NOTICE("  DigestSizes        :\n");

	for (i = 0U; i < number_of_algorithms; ++i) {
		uint16_t algorithm_id = alg_ptr[i].algorithm_id;
		algo_info = event_log_algorithm_lookup(algorithm_id);

		if (algo_info == NULL) {
			ERROR("    #%u AlgorithmId   : %d (unknown)\n", i,
			      algorithm_id);
			return -ENOENT;
		}

		NOTICE("    #%u AlgorithmId   : %s\n", i, algo_info->name);
		NOTICE("       DigestSize    : %u\n", alg_ptr[i].digest_size);
	}

	/* Address of VendorInfoSize */
	info_size_ptr = (uint8_t *)((uintptr_t)alg_ptr + digest_len);
	if ((uintptr_t)info_size_ptr > (uintptr_t)end_ptr) {
		return -EFAULT;
	}

	info_size = *info_size_ptr++;
	NOTICE("  VendorInfoSize     : %u\n", info_size);

	/* Check VendorInfo end address */
	if (((uintptr_t)info_size_ptr + info_size) > (uintptr_t)end_ptr) {
		return -EFAULT;
	}

	/* Check EventSize */
	if (event_size !=
	    (sizeof(id_event_struct_t) + digest_len + info_size)) {
		return -EFAULT;
	}

	event_log_print_spaced_hex(info_size_ptr, info_size,
				   "  VendorInfo         : ");

	*log_size -= (uintptr_t)info_size_ptr - (uintptr_t)*log_addr;
	*log_addr = info_size_ptr;

	return 0;
}

/**
 * Print a TCG_PCR_EVENT2 entry from the event log.
 *
 * This function extracts and prints a TCG_PCR_EVENT2 structure
 * from the event log for debugging or auditing purposes.
 *
 * @param[in,out] log_addr  Pointer to the current position in the Event Log.
 *                          Updated to the next entry after processing.
 * @param[in,out] log_size  Pointer to the remaining Event Log size.
 *                          Updated to reflect the remaining bytes.
 *
 * @return 0 on success, or a negative error code on failure.
 */
static int event_log_print_pcr_event2(uint8_t **log_addr, size_t *log_size)
{
	uint32_t event_size, count;
	void *ptr = *log_addr;
	const struct event_log_algorithm *algo_info;
	const uint8_t *end_ptr = (uint8_t *)((uintptr_t)*log_addr + *log_size);

	if (*log_size < sizeof(event2_header_t)) {
		return -EINVAL;
	}

	NOTICE("PCR_Event2:\n");
	NOTICE("  PCRIndex           : %u\n",
	       ((event2_header_t *)ptr)->pcr_index);
	NOTICE("  EventType          : %u\n",
	       ((event2_header_t *)ptr)->event_type);

	count = ((event2_header_t *)ptr)->digests.count;
	if (count < 1U) {
		NOTICE("Invalid Digests Count      : %u\n", count);
		return -EINVAL;
	}

	NOTICE("  Digests Count      : %u\n", count);

	/* Address of TCG_PCR_EVENT2.Digests[] */
	ptr = (uint8_t *)ptr + sizeof(event2_header_t);
	if ((uintptr_t)ptr > (uintptr_t)end_ptr) {
		return -EFAULT;
	}

	for (unsigned int i = 0U; i < count; ++i) {
		/* Check AlgorithmId address */
		if (((uintptr_t)ptr + offsetof(tpmt_ha, digest)) >
		    (uintptr_t)end_ptr) {
			return -EFAULT;
		}

		algo_info = event_log_algorithm_lookup(
			((tpmt_ha *)ptr)->algorithm_id);

		if (algo_info == NULL) {
			ERROR("    #%u AlgorithmId   : %d (unknown)\n", i,
			      ((tpmt_ha *)ptr)->algorithm_id);
			return -ENOENT;
		}

		NOTICE("    #%u AlgorithmId   : %s\n", i, algo_info->name);

		/* End of Digest[] */
		ptr = (uint8_t *)((uintptr_t)ptr + offsetof(tpmt_ha, digest));
		if (((uintptr_t)ptr + algo_info->size) > (uintptr_t)end_ptr) {
			return -EFAULT;
		}

		event_log_print_digest(ptr, algo_info->size);
		ptr += algo_info->size;
	}

	/* TCG_PCR_EVENT2.EventSize */
	if (((uintptr_t)ptr + offsetof(event2_data_t, event)) >
	    (uintptr_t)end_ptr) {
		return -EFAULT;
	}

	event_size = ((event2_data_t *)ptr)->event_size;
	NOTICE("  EventSize          : %u\n", event_size);

	/* Address of TCG_PCR_EVENT2.Event[EventSize] */
	ptr = (uint8_t *)((uintptr_t)ptr + offsetof(event2_data_t, event));

	/* End of TCG_PCR_EVENT2.Event[EventSize] */
	if (((uintptr_t)ptr + event_size) > (uintptr_t)end_ptr) {
		return -EFAULT;
	}

	if ((event_size == sizeof(startup_locality_event_t)) &&
	    (strcmp((const char *)ptr, TCG_STARTUP_LOCALITY_SIGNATURE) == 0)) {
		NOTICE("  Signature          : %s\n",
		       ((startup_locality_event_t *)ptr)->signature);
		NOTICE("  StartupLocality    : %u\n",
		       ((startup_locality_event_t *)ptr)->startup_locality);
	} else {
		NOTICE("  Event              : %s\n", (uint8_t *)ptr);
	}

	*log_size -= (uintptr_t)ptr + event_size - (uintptr_t)*log_addr;
	*log_addr = (uint8_t *)ptr + event_size;

	return 0;
}

int event_log_dump(uint8_t *log_addr, size_t log_size)
{
	int rc;

	if (log_addr == NULL) {
		return -EINVAL;
	}

	/* Print TCG_EfiSpecIDEvent */
	rc = event_log_print_id_event(&log_addr, &log_size);

	if (rc < 0) {
		return rc;
	}

	while (log_size != 0U) {
		rc = event_log_print_pcr_event2(&log_addr, &log_size);
		if (rc < 0) {
			return rc;
		}
	}
	return 0;
}
