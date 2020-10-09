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
    // PRINTF("    raw bytes:\n");
    // PRINTF("%.*h\n", atom_bytes_window->interval.byteCount, atom_bytes_window->bytes);
    // PRINTF("^^^^^^^^ end of atom bytes ^^^^^^^^^\n");
}

void do_update_atom_bytes_window_by_sliding_bytes_since_parsed_field(
    AtomBytesWindow *atom_bytes_window,
    ParticleField *parsed_particle_field
) {
        uint16_t last_end = get_end_of_atom_bytes_window(atom_bytes_window);
        uint16_t last_start =  atom_bytes_window->interval.startsAt;
        uint16_t last_byte_count_window =  atom_bytes_window->interval.byteCount;
        uint16_t new_start = end_index(&parsed_particle_field->byte_interval);
        uint16_t number_of_skipped_bytes = new_start - last_start;
        uint16_t new_byte_count_window = last_end - new_start;
        atom_bytes_window->interval.startsAt = new_start;
        atom_bytes_window->interval.byteCount = new_byte_count_window;

        assert(number_of_skipped_bytes + new_byte_count_window == last_byte_count_window);
        
        os_memcpy(
            atom_bytes_window->bytes, // destination
            atom_bytes_window->bytes + number_of_skipped_bytes, // source
            new_byte_count_window                                // length
        );
        assert(last_end == get_end_of_atom_bytes_window(atom_bytes_window));
}

void do_update_atom_bytes_window_with_new_bytes(
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