bool sha256_hash(
    cx_sha256_t *hash_context,
    const uint8_t *bytes_to_hash, size_t byte_count, // INPUT

    bool should_finalize_else_update, // If this is set to FALSE, the `output_hash_digest` is not use
    uint8_t *output_hash_digest // OUTPUT length 32 bytes
);


void update_hash_and_maybe_finalize(
    uint8_t* bytes, 
    uint16_t byte_count, 
    bool should_finalize_hash,
    cx_sha256_t *hasher,
    uint8_t* output_bytes
);