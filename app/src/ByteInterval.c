#include "ByteInterval.h"
#include <os.h>

uint16_t end_index(ByteInterval *interval) {
    return interval->startsAt + interval->byteCount;
}

bool is_interval_empty(ByteInterval *interval) {
    return interval->byteCount == 0;
}

void print_interval(ByteInterval *interval) {
    PRINTF("[%d-%d] (#%d bytes)", interval->startsAt, end_index(interval), interval->byteCount);
}

void zero_out_interval(ByteInterval *interval) {
    interval->byteCount = 0;
    interval->startsAt = 0;
}