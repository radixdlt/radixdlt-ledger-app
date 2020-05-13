#include <stdint.h>
#include <stdbool.h>

// Convert "bytes" of length "length" into decimal digits in "buffer", returning the length
uint16_t convertDecimalInto(uint8_t *bytes, int length, char *buffer);

// Convert "bytes" of length "length" into base58 digits in "buffer", returning the length
uint16_t convertBase58Into(uint8_t *bytes, int length, char *buffer);