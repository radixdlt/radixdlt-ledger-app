
// #include <stdint.h>
// #include <stdbool.h>
// #include <os.h>
// #include <os_io_seproxyhal.h>
// #include "apdu_constants.h"
// #include "bip32.h"

// void deriveAndSign(
// 	uint32_t bip32_path_account, 
// 	uint32_t bip32_path_change, 
// 	uint32_t bip32_path_addressIndex, 
// 	bool use_deterministic_signing,
// 	const uint8_t *input_hash, unsigned short input_hash_byte_count,
// 	uint8_t *output_destination,  unsigned short output_byte_count
// ) {

// 	cx_ecfp_private_key_t privateKey;

//     deriveRadixKeypair(
//         bip32_path_account,
//         bip32_path_change,
//         bip32_path_addressIndex,
//         &privateKey,
//         NULL // public key
//     );

// 	if (input_hash_byte_count != ECDSA_SIGNATURE_INPUT_HASH_EXPECTED_BYTE_COUNT) {
// 		THROW(RADIX_SW_HASH_NOT_32_BYTES);
// 	}

//     if (output_byte_count != ECDSA_SIGNATURE_OUTPUT_BYTE_COUNT) {
// 		THROW(RADIX_SW_ALLOCATED_MEMORY_FOR_OUTPUT_SIGNATURE_NOT_64_BYTES);
// 	}

// 	unsigned char rfc6979 = 0;
// 	if (use_determinstic) {
// 		rfc6979 = 1;
// 	}

// 	unsigned int info = 0;
// 	 cx_ecdsa_sign(
// 		&privateKey,
//         CX_LAST | (rfc6979 ? CX_RND_RFC6979 : CX_RND_TRNG),
//         CX_SHA256, 
// 		input_hash, 
// 		input_hash_byte_count, 
// 		output_destination, 
// 		output_byte_count, 
// 		&info
// 	);

// 	// Set CX_ECCINFO_PARITY_ODD if Y is odd when computing k.G
// 	// from: https://github.com/LedgerHQ/blue-secure-sdk/blob/master/include/cx.h#L2369-L2370
// 	if (info & CX_ECCINFO_PARITY_ODD) {
//        output_destination[0] |= 0x01;
//     }

// 	os_memset(&privateKey, 0, sizeof(privateKey));
// }

// // handleSignHash is the entry point for the `deriveAndSign` command. It
// // reads the command parameters, prepares and displays the approval screen,
// // and sets the IO_ASYNC_REPLY flag.
// void handleSignHash(
// 	uint8_t p1, 
// 	uint8_t p2,
// 	uint8_t *dataBuffer, 
// 	uint16_t dataLength, 
// 	volatile unsigned int *flags, 
// 	volatile unsigned int *output_response_apdu_size_aka_tx
// ) {

//     if (dataLength != SIGN_HASH_INS_PAYLOAD_EXPECTED_BYTE_COUNT) {
//         THROW(RADIX_SW_INS_SIGN_HASH_DATA_INPUT_WRONG_SIZE);
//     }

// 	uint32_t bip32_path_account = U4LE(dataBuffer, 0 * BIP32_PATH_COMPONENT_BYTE_COUNT);
// 	uint32_t bip32_path_change = U4LE(dataBuffer, 1 * BIP32_PATH_COMPONENT_BYTE_COUNT);
// 	uint32_t bip32_path_addressIndex = U4LE(dataBuffer, 2 * BIP32_PATH_COMPONENT_BYTE_COUNT);

// 	// Read the hash.
// 	os_memmove(
// 		ctx->hash, // destination
// 		dataBuffer + BIP32_PATH_COMPONENTS_INPUT_EXPECTED_BYTE_COUNT,  // source
// 		sizeof(ctx->hash) // length
// 	);

// 	deriveAndSign(
// 		bip32_path_account,
// 		bip32_path_change,
// 		bip32_path_addressIndex,
// 		true, // use deterministic signing 
// 		ctx->hash, sizeof(ctx->hash),

// 			// const uint8_t *input_hash, unsigned short input_hash_byte_count,
// 	// uint8_t *output_destination,  unsigned short output_byte_count
// 	);
// }