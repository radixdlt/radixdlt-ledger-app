#ifndef BYTEINTERVAL_H
#define BYTEINTERVAL_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
	uint16_t start_index_in_atom;
	uint16_t byte_count;
} byte_interval_t;

uint16_t end_index(byte_interval_t *interval);

bool is_interval_empty(byte_interval_t *interval);

void print_interval(byte_interval_t *interval);

void zero_out_interval(byte_interval_t *interval);

#endif