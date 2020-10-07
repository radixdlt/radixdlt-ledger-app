#ifndef BYTEINTERVAL_H
#define BYTEINTERVAL_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
	uint16_t startsAt;
	uint16_t byteCount;
} ByteInterval;

uint16_t end_index(ByteInterval *interval);

bool is_interval_empty(ByteInterval *interval);

void print_interval(ByteInterval *interval);

void zero_out_interval(ByteInterval *interval);

#endif