#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "radix.h"
#include "ux.h"
#include "cbor.h"

static bool decode_cbor_string(
    const uint8_t *input_cbor_bytes,
    size_t intput_byte_count,
	char *output_string,
    size_t *output_length_of_string
) {
    CborParser parser;
    CborValue value;

    cbor_parser_init(
        input_cbor_bytes,
        intput_byte_count,
        0,
        &parser,
        &value
    );

    if (!cbor_value_is_text_string(&value)) {
        // NOT a string
        PRINTF("cbor_value_is_text_string is false\n");
        return false;
    }

    int string_length;
    cbor_value_calculate_string_length(&value, &string_length);

    // if (string_length > input_max_length_of_output_string) {
    //     PRINTF("string_length > input_max_length_of_output_string\n");
    //     // String too long
    //     return false;
    // }

    CborError error = cbor_value_copy_text_string(
        &value, 
        output_string, 
        &string_length,
        NULL // "next" pointer
    );

    if (error) {
        PRINTF("Got error: %s\n", cbor_error_string(error));
        return false;
    }
    
    *output_length_of_string = string_length;
    return true;
}

// p1, p2 not used
// 
// `dataLength` ought to be min 
// `dataBuffer`: CBOR encode atom bytes
// 
void handleSignAtom(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx) {
    PRINTF("Doing CBOR decoding, received %u bytes\n", dataLength);

    bool successfullyDecodedCbor = decode_cbor_string(
        dataBuffer,
        dataLength,
        G_io_apdu_buffer,
        &tx
    );
    if (successfullyDecodedCbor) {
        PRINTF("tx: %u\n", tx);
        PRINTF("Decoded string: '%.*s'\n", tx, G_io_apdu_buffer);
        // os_memmove(G_io_apdu_buffer, output, tx);
        io_exchange_with_code(SW_OK, tx);
    } else {
        PRINTF("Failed to decode string => throwing error\n");
        THROW(0x9444);
    }

}
	