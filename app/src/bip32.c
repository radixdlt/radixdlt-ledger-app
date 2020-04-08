#include <stdbool.h>
#include <stdint.h>
#include <os.h>
#include <cx.h>
#include "apdu_constants.h"

#include "bip32.h"

void bip32PathFromComponents(
	uint32_t bip32_path_account, 
	uint32_t bip32_path_change, 
	uint32_t bip32_path_addressIndex,
	const uint8_t *output_bip32_path, 
	unsigned short output_bip32_path_byte_count
) {
	if (output_bip32_path_byte_count != BIP32_PATH_FULL_BYTE_COUNT) {
		THROW(SW_INCORRECT_LENGTH);
	}

	// bip32 path for 44'/536'/account/change/addressIndex
	uint32_t bip32Path[] = {
		44 | 0x80000000, // 44'
		536 | 0x80000000,  // 536' - not yet registerd BIP44 coin type of Radix (sum of ascii of 'r', 'a', 'd', 'i', 'x')
		bip32_path_account | 0x80000000, // make account hardened 
		bip32_path_change, // 1 or 0
		bip32_path_addressIndex
	};

	os_memset(output_bip32_path, &bip32Path, sizeof(bip32Path));
}

void deriveRadixKeypairFromThreeComponents(
	uint32_t bip32_path_account, 
	uint32_t bip32_path_change, 
	uint32_t bip32_path_addressIndex, 
	cx_ecfp_private_key_t *privateKey, 
	cx_ecfp_public_key_t *publicKey
) {

	if (bip32_path_change != 0 || bip32_path_change != 1) {
		THROW(RADIX_SW_BIP32_CHANGE_NOT_ZERO_OR_ONE);
	}

	uint8_t bip32Path[BIP32_PATH_FULL_BYTE_COUNT];
	bip32PathFromComponents(
		bip32_path_account,
		bip32_path_change,
		bip32_path_addressIndex,
		&bip32Path,
		sizeof(bip32Path)
	);

	deriveRadixKeypairFromBip32Path(
		&bip32Path,
		privateKey,
		publicKey
	);
}


void deriveRadixKeypairFromBip32Path(
	const uint8_t *bip32Path, 
	cx_ecfp_private_key_t *privateKey, 
	cx_ecfp_public_key_t *publicKey
) {
	uint8_t keySeed[32];
	cx_ecfp_private_key_t secretKey;

	os_perso_derive_node_bip32(
		CX_CURVE_SECP256K1, // Which elliptic Curve
		bip32Path, 			// Derivation path
		5, 					// Derivation path length
		keySeed, 			// privateKey pointer
		NULL				// chain
	);

	cx_ecfp_init_private_key(
		CX_CURVE_SECP256K1,	// Which elliptic Curve
		keySeed,			// rawKey
		sizeof(keySeed),	// length of key
		&secretKey			// returned key
	);
	
	if (publicKey) {
		
		cx_ecfp_init_public_key(
			CX_CURVE_SECP256K1, // Which elliptic Curve
			NULL,				// rawKey
			0,					// key_len
			publicKey			// publicKey pointer
		);

		cx_ecfp_generate_pair(
			CX_CURVE_SECP256K1, // Which elliptic Curve
			publicKey, 			// publicKey pointer
			&secretKey, 		// privateKey pointer
			1					// keep private ?
		);
	}
	if (privateKey) {
		*privateKey = secretKey;
	}
	os_memset(keySeed, 0, sizeof(keySeed));
	os_memset(&secretKey, 0, sizeof(secretKey));
}

void extractPubkeyBytes(unsigned char *dst, cx_ecfp_public_key_t *publicKey) {
	for (int i = 0; i < 32; i++) {
		dst[i] = publicKey->W[64 - i];
	}
	if (publicKey->W[32] & 1) {
		dst[31] |= 0x80;
	}
}

void bin2hex(
	uint8_t *dst, 
	uint8_t *data, 
	uint64_t inlen
) {
	static uint8_t const hex[] = "0123456789abcdef";
	for (uint64_t i = 0; i < inlen; i++) {
		dst[2*i+0] = hex[(data[i]>>4) & 0x0F];
		dst[2*i+1] = hex[(data[i]>>0) & 0x0F];
	}
	dst[2*inlen] = '\0';
}

int bin2dec(uint8_t *dst, uint64_t n) {
	if (n == 0) {
		dst[0] = '0';
		dst[1] = '\0';
		return 1;
	}
	// determine final length
	int len = 0;
	for (uint64_t nn = n; nn != 0; nn /= 10) {
		len++;
	}
	// write digits in big-endian order
	for (int i = len-1; i >= 0; i--) {
		dst[i] = (n % 10) + '0';
		n /= 10;
	}
	dst[len] = '\0';
	return len;
}