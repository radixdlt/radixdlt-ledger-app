#include "byte_interval.h"
#include <os.h>

uint16_t end_index(byte_interval_t *interval) {
    return interval->startsAt + interval->byteCount;
}

bool is_interval_empty(byte_interval_t *interval) {
    return interval->byteCount == 0;
}

void print_interval(byte_interval_t *interval) {
    PRINTF("[%d-%d] (#%d bytes)", interval->startsAt, end_index(interval), interval->byteCount);
}

void zero_out_interval(byte_interval_t *interval) {
    interval->byteCount = 0;
    interval->startsAt = 0;
}