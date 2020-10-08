#include "AtomBytesWindow.h"

void empty_bytes(AtomBytesWindow *atom_bytes_window) {
    explicit_bzero(atom_bytes_window->bytes, MAX_ATOM_SLICE_SIZE);
}

void do_cache_bytes(
    AtomBytesWindow *atom_bytes_window,
    uint8_t *bytes_to_cache,
    const uint16_t number_of_bytes_to_cache
) {
    PRINTF("number_of_bytes_to_cache: %d\n", number_of_bytes_to_cache);

    assert(number_of_bytes_to_cache <= MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS);
    assert(atom_bytes_window->number_of_cached_bytes_from_last_payload == 0);

    empty_bytes(atom_bytes_window);

    os_memcpy(
        atom_bytes_window->bytes,
        bytes_to_cache,
        number_of_bytes_to_cache
    );

    atom_bytes_window->number_of_cached_bytes_from_last_payload = number_of_bytes_to_cache;
}

void do_print_atom_bytes_window(AtomBytesWindow *atom_bytes_window) {
    PRINTF("Atom bytes window\n    ");
    print_interval(&atom_bytes_window->interval);
    PRINTF(" #%d cached bytes\n", atom_bytes_window->number_of_cached_bytes_from_last_payload);
}

void do_update_atom_bytes_window(
    AtomBytesWindow *atom_bytes_window,
    uint8_t *bytes,
    uint16_t number_of_processed_bytes_before_this_payload,
    uint16_t number_of_newly_received_atom_bytes
) {

    uint8_t number_of_cached_bytes_from_last_payload = atom_bytes_window->number_of_cached_bytes_from_last_payload;
    atom_bytes_window->number_of_cached_bytes_from_last_payload = 0;

    uint16_t number_of_bytes_to_process = number_of_newly_received_atom_bytes + number_of_cached_bytes_from_last_payload;

    atom_bytes_window->interval = (ByteInterval) {
        .startsAt = number_of_processed_bytes_before_this_payload,
        .byteCount = number_of_bytes_to_process
    };

    os_memcpy(
        atom_bytes_window->bytes + number_of_cached_bytes_from_last_payload,
        bytes,
        number_of_newly_received_atom_bytes
    );
}

uint16_t get_end_of_atom_bytes_window(AtomBytesWindow *atom_bytes_window) {
    return end_index(&atom_bytes_window->interval);
}

uint16_t get_start_of_atom_bytes_window(AtomBytesWindow *atom_bytes_window) {
    return atom_bytes_window->interval.startsAt;
}