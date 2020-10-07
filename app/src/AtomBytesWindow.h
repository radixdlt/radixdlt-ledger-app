#ifndef ATOMBYTESWINDOW_H
#define ATOMBYTESWINDOW_H


#include "ByteInterval.h"
#include "common_macros.h"

typedef struct {
	uint8_t number_of_cached_bytes_from_last_payload;
	ByteInterval interval;
   	uint8_t bytes[MAX_ATOM_SLICE_SIZE];
} AtomBytesWindow;


void empty_bytes(AtomBytesWindow *atom_bytes_window);

void do_update_atom_bytes_window(
    AtomBytesWindow *atom_bytes_window,
    uint8_t *bytes,
    uint16_t number_of_processed_bytes_before_this_payload,
    uint16_t number_of_newly_received_atom_bytes
);

void do_cache_bytes(
    AtomBytesWindow *atom_bytes_window,
    uint8_t *bytes_to_cache,
    const uint16_t number_of_bytes_to_cache
);

uint16_t get_end_of_atom_bytes_window(AtomBytesWindow *atom_bytes_window);

#endif