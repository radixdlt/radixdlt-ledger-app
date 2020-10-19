#include "byte_interval.h"
#include <os.h>

uint16_t end_index(byte_interval_t *interval) {
    return interval->start_index_in_atom + interval->byte_count;
}

bool is_interval_empty(byte_interval_t *interval) {
    return interval->byte_count == 0;
}

void print_interval(byte_interval_t *interval) {
    PRINTF("[%d-%d] (#%d bytes)", interval->start_index_in_atom, end_index(interval), interval->byte_count);
}

void zero_out_interval(byte_interval_t *interval) {
    interval->byte_count = 0;
    interval->start_index_in_atom = 0;
}