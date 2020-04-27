#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "radix.h"
#include "ux.h"
#include "cbor.h"

// static char *repeatStr(char *str, size_t count) {
//     if (count == 0) return NULL;
//     char *ret = malloc (strlen (str) * count + count);
//     if (ret == NULL) return NULL;
//     strcpy (ret, str);
//     while (--count > 0) {
//         strcat (ret, " ");
//         strcat (ret, str);
//     }
//     return ret;
// }


cx_sha256_t sha2;
static bool sha256_hash(
    const uint8_t *bytes_to_hash, size_t byte_count, // INPUT
    uint8_t *output_hash_digest // OUTPUT length 32 bytes
) {
    if (!bytes_to_hash) {
        PRINTF("'sha256_hash': variable 'bytes_to_hash' is NULL, returning 'false'\n");
        return false;
    }

    if (byte_count <= 0) {
        PRINTF("'sha256_hash': variable 'byte_count' LEQ 0, returning 'false'\n");
        return false;
    }


    if (!output_hash_digest) {
        PRINTF("'sha256_hash': variable 'output_hash_digest' is null, returning 'false'\n");
        return false;
    }

    cx_sha256_init(&sha2);

    cx_hash(
        &sha2.header, 
        CX_LAST, 
        bytes_to_hash, byte_count, 
        output_hash_digest, 
        32
    );

    return true;
}

static char* create_deadbeef_n_times(const unsigned int times) {
    // char deadbeef_string[times*8 + 1]; // +1 for null
    // for (unsigned int i = 0; i < times; ++i) {
    //     *deadbeef_string = "deadbeef";
    //     deadbeef_string = deadbeef_string + 8;
    // }
    // return deadbeef_string;
    unsigned int count = times;
    if (count == 0) return NULL;
    int substr_length = 8;
    char *str = "deadbeef";//\0";
    // char *ret = malloc(strlen(str) * count + count);
    char ret[times*substr_length + 1];
    if (ret == NULL) return NULL;
    strcpy(ret, str);
    int str_length = 0;
    while (--count > 0) {
        // strcat (ret, " ");
        strcat(ret, str);
        str_length += substr_length;
    }
    ret[times*substr_length] = '\0';
    return ret;
}

// p1, p2 not used
// 
// `dataLength` ought to be min 
// `dataBuffer`: CBOR encode atom bytes
// 
void handleSignAtom(
    uint8_t p1, 
    uint8_t p2, 
    uint8_t *dataBuffer, 
    uint16_t dataLength, 
    volatile unsigned int *flags, 
    volatile unsigned int *tx
) {
    PRINTF("handleSignAtom, received %u bytes\n, p1=%u, p2=%u\n", dataLength, p1, p2);
    char *string = create_deadbeef_n_times(16);
    size_t string_size = strlen(string);
    PRINTF("\nGenerated string:\n%s\nstring_size: %d\nNow hashing it...\n", string, string_size);
    uint8_t hashed[32];
    if(!sha256_hash(string, string_size, hashed)) {
        PRINTF("Failed to hash string\n");
    } else {
        PRINTF("Hashed results in hex: %.*h\nDONE! Bye bye!\n", 32, hashed);
    }

    io_exchange_with_code(SW_OK, 0);
}
	