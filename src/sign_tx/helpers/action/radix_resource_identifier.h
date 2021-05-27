#ifndef RADIXRESOURCEIDENTIFIER_H
#define RADIXRESOURCEIDENTIFIER_H

#include <stdint.h>
#include <stdbool.h>

#define RADIX_RRI_MAX_LENGTH_SYMBOL 14
#define RADIX_RRI_MAX_BYTE_COUNT 70
#define RADIX_RRI_STRING_LENGTH_MAX 100 // inaccurate... TODO fix this

/* A Radix resource identifier is a human readable index into the Ledger which points to a name state machine */
typedef struct {
    /* e.g.: `"foo_rb1qv9ee5j4qun9frqj2mcg79maqq55n46u5ypn2j0g9c3q32j6y3"` */
    uint8_t bytes[RADIX_RRI_MAX_BYTE_COUNT];
} radix_resource_identifier_t;

size_t to_string_rri(
    radix_resource_identifier_t *rri,
    char *output_buffer,
    const size_t size_of_buffer,
    bool skip_address
);

size_t to_string_rri_null_term_or_not(
    radix_resource_identifier_t *rri,
    char *output_buffer,
    const size_t size_of_buffer,
    bool skip_address,
    bool null_terminate);

void print_radix_resource_identifier(radix_resource_identifier_t *rri);

#endif
