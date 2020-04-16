// macros for converting raw bytes to uint64_t
#define U8BE(buf, off) (((uint64_t)(U4BE(buf, off))     << 32) | ((uint64_t)(U4BE(buf, off + 4)) & 0xFFFFFFFF))
#define U8LE(buf, off) (((uint64_t)(U4LE(buf, off + 4)) << 32) | ((uint64_t)(U4LE(buf, off))     & 0xFFFFFFFF))

// bin2hex converts binary to hex and appends a final NUL byte.
void bin2hex(uint8_t *dst, uint8_t *data, uint64_t inlen);

// bin2dec converts an unsigned integer to a decimal string and appends a
// final NUL byte. It returns the length of the string.
int bin2dec(uint8_t *dst, uint64_t n);

// extractPubkeyBytes converts a Ledger-style public key to a Radix-friendly
// 32-byte array.
void extractPubkeyBytes(unsigned char *dst, cx_ecfp_public_key_t *publicKey);

void deriveRadixKeypairFromThreeComponents(
	uint32_t bip32_path_account, 
	uint32_t bip32_path_change, 
	uint32_t bip32_path_addressIndex, 
	cx_ecfp_private_key_t *privateKey, 
	cx_ecfp_public_key_t *publicKey
);

void deriveRadixKeypairFromBip32Path(
    const uint32_t *bip32Path,
    uint32_t pathLength,
	cx_ecfp_private_key_t *privateKey, 
	cx_ecfp_public_key_t *publicKey
);

void bip32PathFromComponents(
	uint32_t bip32_path_account, 
	uint32_t bip32_path_change, 
	uint32_t bip32_path_addressIndex,
	uint32_t *output_bip32_path, 
	uint64_t output_bip32_path_byte_count
);
