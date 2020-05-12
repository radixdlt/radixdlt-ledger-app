#include <stdint.h>

#define RADIX_RRI_MAX_BYTE_COUNT 70

/* A Radix resource identifier is a human readable index into the Ledger which points to a name state machine */
typedef struct {
    /* On format: `/:address/:name`, e.g.: `"/JH1P8f3znbyrDj8F4RWpix7hRkgxqHjdW2fNnKpR3v6ufXnknor/XRD"` */
    uint8_t bytes[RADIX_RRI_MAX_BYTE_COUNT];
} RadixResourceIdentifier;
