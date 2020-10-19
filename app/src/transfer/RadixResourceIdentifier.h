#ifndef RADIXRESOURCEIDENTIFIER_H
#define RADIXRESOURCEIDENTIFIER_H


#include <stdint.h>
#include "RadixAddress.h"

#define RADIX_RRI_MAX_BYTE_COUNT 70
#define RADIX_RRI_MAX_LENGTH_SYMBOL 14
#define RADIX_RRI_STRING_LENGTH_MAX (1 + RADIX_ADDRESS_BASE58_CHAR_COUNT_MAX + 1 + RADIX_RRI_MAX_LENGTH_SYMBOL + 1) // +1 for "/" + len(addrB58) +1 for "/" + len(Symbol) + NULL term 

/* A Radix resource identifier is a human readable index into the Ledger which points to a name state machine */
typedef struct {
    /* On format: `/:address/:name`, e.g.: `"/JH1P8f3znbyrDj8F4RWpix7hRkgxqHjdW2fNnKpR3v6ufXnknor/XRD"` */
    uint8_t bytes[RADIX_RRI_MAX_BYTE_COUNT];
} RadixResourceIdentifier;

size_t to_string_rri(
    RadixResourceIdentifier *rri,
    char *output_buffer,
    const size_t size_of_buffer,
    bool skip_address
);

size_t to_string_rri_null_term_or_not(
    RadixResourceIdentifier *rri,
    char *output_buffer,
    const size_t size_of_buffer,
    bool skip_address,
    bool null_terminate);

void printRRI(RadixResourceIdentifier *rri);

#endif