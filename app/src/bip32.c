#include <stdbool.h>
#include <stdint.h>
#include <os.h>
#include <cx.h>
#include "apdu_constants.h"
#include "zxmacros.h"
#include "bip32.h"

void bip32PathFromComponents(
	uint32_t bip32_path_account, 
	uint32_t bip32_path_change, 
	uint32_t bip32_path_addressIndex,
	uint32_t *output_bip32_path,
	uint64_t output_bip32_path_byte_count
) {

	// if (output_bip32_path_byte_count != BIP32_PATH_FULL_BYTE_COUNT) {
	// 	THROW(SW_INCORRECT_LENGTH);
	// }

	if (!(bip32_path_change == 0 || bip32_path_change == 1)) {
		THROW(0x9500);
	}

	// bip32 path for 44'/536'/account/change/addressIndex
	uint32_t bip32Path[] = {
		44 | 0x80000000, // 44'
		0 | 0x80000000,  // 536' - not yet registerd BIP44 coin type of Radix (sum of ascii of 'r', 'a', 'd', 'i', 'x')
		bip32_path_account | 0x80000000, // make account hardened 
		bip32_path_change, // 1 or 0
		bip32_path_addressIndex
	};

	os_memcpy(output_bip32_path, bip32Path, 20);
}

void deriveRadixKeypairFromThreeComponents(
	uint32_t bip32_path_account, 
	uint32_t bip32_path_change, 
	uint32_t bip32_path_addressIndex, 
	cx_ecfp_private_key_t *privateKey, 
	cx_ecfp_public_key_t *publicKey
) {

	if (!(bip32_path_change == 0 || bip32_path_change == 1)) {
		THROW(0x9499);
	}

	uint32_t bip32Path[BIP32_PATH_FULL_NUMBER_OF_COMPONENTS];

	bip32PathFromComponents(
		bip32_path_account,
		bip32_path_change,
		bip32_path_addressIndex,
		bip32Path,
		sizeof(bip32Path)
	);

	deriveRadixKeypairFromBip32Path(
		bip32Path,
		5,
		privateKey,
		publicKey
	);
}


// void deriveRadixKeypairFromBip32Path(
// 	uint32_t *bip32Path, 
// 	cx_ecfp_private_key_t *privateKey, 
// 	cx_ecfp_public_key_t *publicKey
// ) {
void deriveRadixKeypairFromBip32Path(
    const uint32_t *bip32Path,
    uint32_t pathLength,
	cx_ecfp_private_key_t *privateKey, 
	cx_ecfp_public_key_t *publicKey
) {

    // unsigned char seed[32];
	PRINTF("APA\n");
	
	PRINTF("deriveRadixKeypairFromBip32Path input bip32 path is: %.*H \n\n", 20, bip32Path);
	

	// PRINTF("HARD CODED bip32 path is: %.*H \n\n", 20, HaRdCoDeD_bIp32_pAtH);

	// os_perso_derive_node_bip32_seed_key(HDW_NORMAL, CX_CURVE_SECP256K1, bip32Path, 5, keySeed, NULL, NULL, 0);


	uint8_t keySeed[32];
	PRINTF("Calling os_perso_derive_node_bip32 block now\n");


    unsigned char chainCode[32];

    BEGIN_TRY
    {
        TRY {
			       // Generate keys
           io_seproxyhal_io_heartbeat();
			os_perso_derive_node_bip32(
				CX_CURVE_256K1,
                bip32Path,
                5,
                keySeed,
                chainCode // chain ???? what is
			);
			io_seproxyhal_io_heartbeat();
				// os_perso_derive_node_bip32_seed_key(
				// 	HDW_NORMAL,
				// 	CX_CURVE_SECP256K1, 
				// 	bip32Path_HARD_CODED, 
				// 	5, 
				// 	keySeed, 
				// 	NULL, 
				// 	NULL, 
				// 	0
				// );

            // SAFE_HEARTBEAT(cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey));
            // SAFE_HEARTBEAT(cx_ecfp_init_public_key(CX_CURVE_256K1, NULL, 0, &cx_publicKey));
            // SAFE_HEARTBEAT(cx_ecfp_generate_pair(CX_CURVE_256K1, &cx_publicKey, &cx_privateKey, 1));
        }
		CATCH_OTHER(e) {
			PRINTF("os_perso_derive_node_bip32 failed with error: %d\n", e);
			
			THROW(e);
		}
        FINALLY {
			PRINTF("FINALLY called\n");
            // MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            // MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;


	PRINTF("EPIC WIN seed: %.*H \n\n", 32, keySeed);

	// PRINTF("seed is: %.*H \n\n", 32, seed);
	// PRINTF("BANAN, WARNING! USING HARDCODED BIP32 PATH!!!\n");

	// cx_ecfp_private_key_t secretKey;

	// cx_ecfp_init_private_key(
	// 	CX_CURVE_SECP256K1,	// Which elliptic Curve
	// 	seed,			// rawKey
	// 	sizeof(seed),	// length of key
	// 	&secretKey			// returned key
	// );
	
	// PRINTF("CITRON\n");
	// if (publicKey) {
		
	// 	cx_ecfp_init_public_key(
	// 		CX_CURVE_SECP256K1, // Which elliptic Curve
	// 		NULL,				// rawKey
	// 		0,					// key_len
	// 		publicKey			// publicKey pointer
	// 	);

	// PRINTF("DUMBO\n");
	// 	cx_ecfp_generate_pair(
	// 		CX_CURVE_SECP256K1, // Which elliptic Curve
	// 		publicKey, 			// publicKey pointer
	// 		&secretKey, 		// privateKey pointer
	// 		1					// keep private ?
	// 	);
	// PRINTF("ELEFANT\n");
	// }
	// if (privateKey) {
	// 	*privateKey = secretKey;
	// }
	// PRINTF("FLUM\n");
	// os_memset(seed, 0, sizeof(seed));
	// PRINTF("GLUGG\n");
	// os_memset(&secretKey, 0, sizeof(secretKey));
	// PRINTF("HUGG\n");

	// THROW(0x9432);
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