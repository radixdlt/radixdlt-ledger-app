#include <stdint.h>
#include <stdbool.h>

// Convert "bytes" of length "length" into digits of base "base" in "buffer", returning the length
uint16_t convertByteBufferIntoDigitsWithBase(uint8_t *bytes, int length, char *buffer, uint8_t base);