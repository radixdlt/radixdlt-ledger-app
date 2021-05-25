#ifndef BASECONVERSION_H
#define BASECONVERSION_H


#include <stdint.h>
#include <stdbool.h>

// Convert "bytes" of length "length" into digits of base 10 in "buffer", returning the length
uint16_t convert_byte_buffer_into_decimal(uint8_t *bytes, int length, char *buffer);

uint16_t hexadecimal_string_from(
    uint8_t *bytes,
    int byte_count, 
    char *output_buffer
);

#endif
