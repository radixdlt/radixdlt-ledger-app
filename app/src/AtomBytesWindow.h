#include "ParticleMetaData.h"
#include "common_macros.h"

typedef struct {
	uint8_t number_of_cached_bytes_from_last_payload;
	ByteInterval interval;
   	uint8_t bytes[MAX_ATOM_SLICE_SIZE];
} AtomBytesWindow;


void empty_bytes(AtomBytesWindow *atom_bytes_window);

void cache_bytes_to_next_chunk(
    uint8_t *bytes_to_cache,
    const uint16_t number_of_bytes_to_cache
);