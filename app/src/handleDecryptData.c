#include "common_macros.h"
#include "stdint.h"
#include "global_state.h"
#include "aes.h"
#include "ui.h"
#include "key_and_signatures.h"
#include "os.h"
#include "crypt.h"
#include <stdio.h>
#include <inttypes.h>
#include <strings.h>
#include "pkcs7_padding.h"
#include "stddef.h"

static decryptDataContext_t *ctx = &global.decryptDataContext;


static void uncompress_and_init_pubkey(
    uint8_t *compressed_pubkey,
    const size_t compressed_pubkey_len,
    cx_ecfp_256_public_key_t *pubkey
) {
    uint8_t pubkey_uncompressed[UNPUBLIC_KEY_COMPRESSEED_BYTE_COUNT];
    uncompress_public_key(compressed_pubkey, compressed_pubkey_len, pubkey_uncompressed, UNPUBLIC_KEY_COMPRESSEED_BYTE_COUNT);
    cx_ecfp_init_public_key(
        CX_CURVE_256K1,
        pubkey_uncompressed, UNPUBLIC_KEY_COMPRESSEED_BYTE_COUNT,
        pubkey
    );
}


static bool sha512Twice(
     const uint8_t *data_in, const size_t data_in_len,
     uint8_t *data_out, const size_t data_out_len
) {

    cx_sha512_init(&(ctx->hasher));
      cx_hash(
          ((cx_hash_t *) (&(ctx->hasher))),
              CX_LAST, 
              data_in, data_in_len,
              data_out,
              data_out_len
    );

    // Once again, since twice
    cx_sha512_init(&(ctx->hasher));
    cx_hash(
        ((cx_hash_t *) (&(ctx->hasher))),
        CX_LAST, 
        data_out, data_out_len,
        data_out,
        data_out_len
    );

}

static void update_hmac(
    uint8_t *data, size_t dataLength
) {
    cx_hmac(
        (cx_hmac_t *)&(ctx->hmac), 
        CX_NO_REINIT, 
        data, data_length, 
        NULL, 
        0
    );
}

static void prepare_decryption_data() {

  // 1. Do an EC point multiply with `privateKey` and ephemeral public key. Call it `pointM` 
    os_memcpy(ctx->pointM, ctx->ephemeral_pubkey.W, UNPUBLIC_KEY_COMPRESSEED_BYTE_COUNT);
    cx_ecfp_scalar_mult(
        CX_CURVE_256K1, 
        ctx->pointM, UNPUBLIC_KEY_COMPRESSEED_BYTE_COUNT, 
        privateKey->d, privateKey->d_len
    );

    // 2. Use the X component of `pointM` and calculate the SHA512 `hashH`.
    sha512Twice(ctx->pointM + 1, 32, ctx->hashH, HASH512_LEN);

    AES_init_ctx_iv(&(ctx->aes_ctx), ctx->hashH, ctx->iv);

    cx_hmac_sha256_init(&(ctx->hmac), ctx->hashH + 32, 32);
    update_hmac(ctx->IV, IV_LEN);
    compress_public_key(&(ctx->ephemeral_pubkey)); // must be done AFTER `pointM` is calculated
    update_hmac(ctx->ephemeral_pubkey.W, PUBLIC_KEY_COMPRESSEED_BYTE_COUNT); 
    // hmac has now been updated with `IV(16) + PubKey(33)`
    // now HMAC needs to be stream updated with whole cipher


}

// Read: BIP32(12) + IV(16) + 0x33(1) + PubKey(33) + CipherTextLength(4) + MAC(32)
// In total: 12+16+1+33+4+32 = 98 bytes
// Please note that this is different from  what all other libraries encrypts! They encrypt:
// IV(16) + 0x33(1) + PubKey(33) + CipherTextLength(4) + CipherText(?) + MAC(32)
// Note the difference, CipherText BEFORE the MAC, but since CipherText is of arbitrary length 
// (`CipherTextLength`) it is simpler to send the MAC first and then stream the CipherText. This
// of wastes 32 bytes (MAC) that needs to be kept in memory but hey it is simpler.
static void parse_input_of_first_chunk(
    uint8_t* dataBuffer,
    uint16_t dataLength
) {
    assert(dataLength == 98);

    // READ BIP32Path (12 bytes)
    uint32_t bip32Path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
    PRINTF("Reading BIP32 path\n");
    parse_bip32_path_from_apdu_command(
        dataBuffer, bip32Path, G_ui_state.lower_line_long,
        BIP32_PATH_STRING_MAX_LENGTH
    );
   
    // FINISHED PARSING INPUT
    PRINTF("deriving key from seed and BIP\n");
    int KEY_SEED_BYTE_COUNT = 32;
    volatile uint8_t keySeed[KEY_SEED_BYTE_COUNT];
    volatile uint16_t error = 0;
    BEGIN_TRY {
        TRY {
            os_perso_derive_node_bip32(CX_CURVE_256K1, bip32Path, 5, keySeed, NULL);
            cx_ecfp_init_private_key(CX_CURVE_SECP256K1, keySeed, 32, &(ctx->privateKey));
        }
        CATCH_OTHER(e) { error = e; }
        FINALLY { explicit_bzero(keySeed, KEY_SEED_BYTE_COUNT); }
    }
    END_TRY;

    if (error) {
        FATAL_ERROR("Error? code: %d\n", error);
    }

    size_t offset = 0;
    size_t copy_byte_count = 0;


     // READ IV (16 bytes)
    copy_byte_count = IV_LEN;
    os_memmove(ctx->iv, dataBuffer + offset, copy_byte_count);
    offset += copy_byte_count;

    // SKIP reading length of PubKeyComp, should be 33
    assert(dataBuffer + BIP32_PATH_LEN + offset == 33);
    offset += 1;

    // READ EphemeralPubKeyComp (33 bytes)
    copy_byte_count = PUBLIC_KEY_COMPRESSEED_BYTE_COUNT;
    uncompress_and_init_pubkey(dataBuffer + offset, copy_byte_count, &(ctx->ephemeral_pubkey));
    offset += copy_byte_count;

    // Read CipherText Length
    ctx->cipher_text_byte_count = U4BE(dataBuffer, offset);
    PRINTF("Length of cipher text: %d\n", ctx->cipher_text_byte_count);
    offset += 4; // length of cipher text is encoded as 4 bytes, hence `U4BE` above

    // size_t offset_cipher_text = offset;
    // offset += cipher_text_length;
    // PRINTF("Cipher text to decrypt: %.*h\n", cipher_text_length, dataBuffer + offset_cipher_text);
    
    // READ MAC (32 bytes)
    copy_byte_count = MAC_LEN;
    os_memcpy(ctx->mac, dataBuffer + offset, copy_byte_count);
    offset += copy_byte_count;

    assert(offset == dataLength);

    // size_t message_for_mac_len = IV_LEN + PUBLIC_KEY_COMPRESSEED_BYTE_COUNT + cipher_text_length;
    // uint8_t message_for_mac[message_for_mac_len];
}


// ==== START ==== UI PROGRESS UPDATE ========
static const ux_menu_entry_t ui_hack_as_menu_progress_update[] = {
	{NULL, NULL, 0, NULL, "Parsing msg", G_ui_state.lower_line_short, 0, 0},
	UX_MENU_END,
};

static void updateProgressDisplay() {
    os_memset(G_ui_state.lower_line_long, 0x00,
              MAX_LENGTH_FULL_STR_DISPLAY);

    os_memset(G_ui_state.lower_line_short, 0x00,
              DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);

    snprintf(
        G_ui_state.lower_line_short, 
        DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE, 
        "Part: %02d/%02d",
        (ctx->cipher_number_of_parsed_bytes/MAX_CHUNK_SIZE),
        (ctx->cipher_text_byte_count/MAX_CHUNK_SIZE)
    );
    
    UX_REDISPLAY_IDX(ux_visible_element_index);
}

static void update_decryption_data_state(
    uint8_t *data_in_out, // IN encrypted bytes, OUT decrypted bytes
    size_t data_length,
    bool is_last
) {
    // update HMAC state
    cx_hmac(
        (cx_hmac_t *)&(ctx->hmac), 
        is_last ? CX_LAST : CX_NO_REINIT, 
        data_in_out, data_length, 
        is_last ? ctx->calc_mac : NULL, 
        is_last ? MAC_LEN : 0
    );

    // update AES state
    AES_CBC_decrypt_buffer(&(ctx->aes_ctx), data_in_out, data_length);
}

// READs bytes from host machine and decrypts them (located in `G_io_apdu_buffer`) 
static bool decrypt_part_of_msg() {
    uint16_t bytesLeftToRead = ctx->cipher_text_byte_count - ctx->cipher_number_of_parsed_bytes;
    uint16_t chunkSize = MIN(MAX_CHUNK_SIZE, bytesLeftToRead);

    os_memset(G_io_apdu_buffer, 0x00, IO_APDU_BUFFER_SIZE);
    G_io_apdu_buffer[0] = 0x90; // 0x9000 == 'SW_OK'
    G_io_apdu_buffer[1] = 0x00; // 0x9000 == 'SW_OK'
    io_exchange(CHANNEL_APDU, 2);

    bool is_last_chunk = (ctx->cipher_number_of_parsed_bytes + chunkSize) >= ctx->cipher_text_byte_count

    // `G_io_apdu_buffer` now contains `chunkSize` relevant bytes
    update_decryption_data_state(G_io_apdu_buffer, chunkSize, is_last_chunk);

    // Sends decrypted chars back to host machine
    io_exchange_with_code(SW_OK, chunkSize);

    ctx->cipher_number_of_parsed_bytes += chunkSize;

    return is_last_chunk;
}

static void stream_decrypt_msg()
{
    bool finished_decrypting_whole_msg = false;
    while (!finished_decrypting_whole_msg)
    {
        finished_decrypting_whole_msg = decrypt_part_of_msg();

        updateProgressDisplay();

        PRINTF("Finished parsing %u/%u bytes of the Atom\n", ctx->cipher_number_of_parsed_bytes, ctx->cipher_text_byte_count);
    }

    assert(ctx->cipher_number_of_parsed_bytes == ctx->cipher_text_byte_count);

    PRINTF("\n\n.-~=*#^^^ FINISHED PARSING ALL CHUNKS ^^^#*=~-.\n\n");

    if (os_memcmp(ctx->calc_mac, ctx->mac, MAC_LEN) != 0) {
        PRINTF("FAILURE! MAC mismatch\n");
	    return 0;
    }
}


void handleDecryptData(
    uint8_t p1, 
    uint8_t p2, 
    uint8_t *dataBuffer,
    
    uint16_t dataLength, 
    unsigned int *flags,
    unsigned int *tx
 ) {
    PRINTF("handleDecryptData\n");


    // ctx->cipher_text_byte_count = p1;
    ctx->cipher_number_of_parsed_bytes = 0;

    parse_input_of_first_chunk(dataBuffer, dataLength);
    prepare_decryption_data();

    stream_decrypt_msg();

    // *flags |= IO_ASYNCH_REPLY;

    // PRINTF("Decryption finished - plaintext: '%.*s'\n", plain_text_len, dataBuffer + BIP32_PATH_LEN);
    // os_memcpy(G_io_apdu_buffer, dataBuffer + BIP32_PATH_LEN, plain_text_len);
    // io_exchange_with_code(SW_OK, plain_text_len);
    PRINTF("\n\n***** DONE *****\n");
}