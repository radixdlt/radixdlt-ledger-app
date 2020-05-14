#include <stdint.h>
#include <stdbool.h>

// Convert "bytes" of length "length" into digits of base 10 in "buffer", returning the length
uint16_t convertByteBufferIntoDecimal(uint8_t *bytes, int length, char *buffer);

// Convert "bytes" of length "length" into digits of base 58 in "buffer", returning the length
uint16_t convertByteBufferIntoBase58(uint8_t *bytes, int length, char *buffer);