#include <stdio.h>
#include <string.h>

#include "event_record.h"

int main(void)
{
	static uint8_t event_log[0x400];
#if (HASH_ALG_COUNT == 1U)
	static uint8_t digest[MAX_DIGEST_SIZE];
#endif
	const char payload[] = "hello event log";
	size_t size_after_header;
	size_t size_after_event;
	size_t expected;

	static tpm_alg_id algos[] = {
		EVLOG_TPM_ALG_SHA256,
#if (HASH_ALG_COUNT == 3U)
		EVLOG_TPM_ALG_SHA384,
		EVLOG_TPM_ALG_SHA512,
#endif
	};

#if (HASH_ALG_COUNT == 1U) || (HASH_ALG_COUNT == 3U)
#else
#error "test expects HASH_ALG_COUNT to be 1 or 3"
#endif

	printf("libeventlog test HASH_ALG_COUNT=%d\n", HASH_ALG_COUNT);
	if (event_log_init(event_log, event_log + sizeof(event_log)) != 0) {
		return 1;
	}

	if (event_log_write_header(algos,
				   (uint32_t)(sizeof(algos) / sizeof(algos[0])),
				   0U, NULL, 0U) != 0) {
		return 1;
	}

	size_after_header = event_log_get_cur_size(event_log);
	printf("size_after_header = %lu\n", size_after_header);
#if (HASH_ALG_COUNT == 1U)
	if (size_after_header != LOG_MIN_SIZE) {
		printf("header size mismatch: got %zu expected %u\n",
		       size_after_header, LOG_MIN_SIZE);
		return 1;
	}

	memset(digest, 0, sizeof(digest));
	if (event_log_write_pcr_event2_single(
		    0, EV_ACTION, EVLOG_TPM_ALG_SHA256, digest,
		    (const uint8_t *)payload, (uint32_t)sizeof(payload)) != 0) {
		return 1;
	}
#else
	if (size_after_header > LOG_MIN_SIZE) {
		printf("header size exceeds upper bound: got %zu expected %u\n",
		       size_after_header, LOG_MIN_SIZE);
		return 1;
	}

	if (event_log_write_pcr_event2(PCR_0, EV_NO_ACTION, NULL,
				       (const uint8_t *)payload,
				       (uint32_t)sizeof(payload)) != 0) {
		return 1;
	}
#endif

	size_after_event = event_log_get_cur_size(event_log);
	expected = LOG_MIN_SIZE + EVENT2_HDR_SIZE + sizeof(payload);
#if (HASH_ALG_COUNT == 1U)
	if (size_after_event != expected) {
		printf("event size mismatch: got %zu expected %zu\n",
		       size_after_event, expected);
		return 1;
	}
#else
	if (size_after_event > expected) {
		printf("event size exceeds upper bound: got %zu expected %zu\n",
		       size_after_event, expected);
		return 1;
	}
#endif

	printf("event log size: %zu bytes\n", size_after_event);
	return 0;
}
