#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "key_and_signatures.h"
#include "ui.h"
#include "global_state.h"
#include "sha256_hash.h"
#include "cbor.h"
#include "base_conversion.h"
#include "signAtomUI.h"
#include "common_macros.h"

static signAtomContext_t *ctx = &global.signAtomContext;

// Please see column "Additional info" in table "CBOR Major types": https://radixdlt.atlassian.net/wiki/spaces/AM/pages/56557727/DSON+Encoding
typedef enum
{
    ByteStringCBORPrefixByte_address = 4,

    // Used for `amount`
    ByteStringCBORPrefixByte_uint256 = 5,

    // Used for `token_definition_reference`
    ByteStringCBORPrefixByte_rri = 6
} CBORBytePrefixForByteArray;

static void printRRI(RadixResourceIdentifier *rri) {
    const size_t max_length = RADIX_RRI_STRING_LENGTH_MAX;
    char rri_utf8_string[max_length];
    to_string_rri(rri, rri_utf8_string, max_length, true);
    PRINTF("%s", rri_utf8_string);
}

static void printTokenAmount(TokenAmount *tokenAmount) {
    const size_t max_length = (UINT256_DEC_STRING_MAX_LENGTH + 1); // +1 for null
    char dec_string[max_length];
    to_string_uint256(tokenAmount, dec_string, max_length);
    PRINTF("%s", dec_string);
}

static void empty_particle_meta_data() {
    explicit_bzero(&ctx->particle_meta_data, sizeof(ParticleMetaData));
    ctx->particle_meta_data.has_relevant_data = false;
}

static void empty_transfer() {
    explicit_bzero(&ctx->transfer, sizeof(Transfer));
    ctx->transfer.has_confirmed_serializer = false;
}

static void empty_atom_slice() {
    explicit_bzero(&ctx->atom_slice, MAX_ATOM_SLICE_SIZE);
}

static void reset_state() {
    ctx->atom_byte_count = 0;
    ctx->number_of_atom_bytes_parsed = 0;
    ctx->non_transfer_data_found = false;
    explicit_bzero(&ctx->bip32_path, NUMBER_OF_BIP32_COMPONENTS_IN_PATH * sizeof(uint32_t));
    empty_particle_meta_data();
    empty_transfer();
    empty_atom_slice();
}

static void initiate_hasher() {
    explicit_bzero(&ctx->hash, HASH256_BYTE_COUNT);
    cx_sha256_init(&ctx->hasher);
}

static void initiate_state() {
    reset_state();
    initiate_hasher();
}

static void empty_buffer() {
    explicit_bzero(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
}

static void parse_bip_and_atom_size(
    uint8_t *dataBuffer,
    const uint16_t dataLength
) {
    // Input validation
    uint16_t expected_number_of_bip32_compents = 3;
    uint16_t byte_count_bip_component = 4;
    uint16_t expected_bip32_byte_count = expected_number_of_bip32_compents * byte_count_bip_component;
    size_t byte_count_of_atom_size = 2;
    uint16_t expected_data_length = expected_bip32_byte_count + byte_count_of_atom_size;
    
    if (dataLength != expected_data_length) {
        FATAL_ERROR("Incorrect 'dataLength', expected: %d, but got: %d", expected_data_length, dataLength);
    }

    // READ BIP32 path (12 bytes)
    parse_bip32_path_from_apdu_command(dataBuffer, ctx->bip32_path, NULL, 0);

    // READ Atom Byte Count (CBOR encoded data, max 2 bytes)
    ctx->atom_byte_count = U2BE(dataBuffer, expected_bip32_byte_count);
}

typedef enum {
    PayloadTypeIsParticleMetaData = 3,
    PayloadTypeIsAtomBytes = 4
} PayloadType;

static void parse_particle_meta_data(
    uint8_t *dataBuffer,
    const uint16_t dataLength
) {
    // READ meta data about particles from first chunk, available directly
    assert(dataLength == 16);
    
    // PRINTF("Received meta data about: #%u particles\n", ctx->numberOfParticlesWithSpinUp);
    PRINTF("Received particle meta data hex string:\n%.*H\n", dataLength, dataBuffer);
    int dataOffset = 0;

    PRINTF("Zeroing out old particle meta data now...\n");
    empty_particle_meta_data();

    // ctx->metaDataAboutParticle.particleItself.startsAt = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    // ctx->metaDataAboutParticle.particleItself.byteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

    ctx->particle_meta_data.addressOfRecipientByteInterval.startsAt = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    ctx->particle_meta_data.addressOfRecipientByteInterval.byteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

    ctx->particle_meta_data.amountByteInterval.startsAt = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    ctx->particle_meta_data.amountByteInterval.byteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

    ctx->particle_meta_data.serializerValueByteInterval.startsAt = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    ctx->particle_meta_data.serializerValueByteInterval.byteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

    ctx->particle_meta_data.token_definition_referenceByteInterval.startsAt = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    ctx->particle_meta_data.token_definition_referenceByteInterval.byteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

    PRINTF("\nFinished parsing particle meta data...\n\n");

    ctx->particle_meta_data.has_relevant_data = true;
}



/// If we just received a new ParticleMetaData this functions returns `0`, otherwise it returns the number of newly
/// recived atom bytes (i.e. bytes that needs to be use to update hash and possibly be parsed)
static uint8_t receive_bytes_from_host_machine() {
    empty_buffer();
    G_io_apdu_buffer[0] = 0x90; // 0x9000 == 'SW_OK'
    G_io_apdu_buffer[1] = 0x00; // 0x9000 == 'SW_OK'
    io_exchange(CHANNEL_APDU, 2);

    uint8_t p1 = G_io_apdu_buffer[OFFSET_P1];
    uint8_t p2 = G_io_apdu_buffer[OFFSET_P2];
    uint8_t* dataBuffer = G_io_apdu_buffer + OFFSET_CDATA;
    uint16_t dataLength = G_io_apdu_buffer[OFFSET_LC];

    PayloadType payloadType = p1;

    switch (payloadType)
    {
    case PayloadTypeIsAtomBytes:
        os_memcpy(
            ctx->atom_slice + ctx->number_of_cached_bytes,
            dataBuffer,
            dataLength
        );
        return dataLength;
    case PayloadTypeIsParticleMetaData:
        parse_particle_meta_data(dataBuffer, dataLength);
        return 0; // Meta Data about Particle is not atom bytes, should not update hash with these
    default:
        FATAL_ERROR("Unrecognized P1 value: %d\n", p1)
    }
}

static void update_hash(uint8_t number_of_atom_bytes_received, uint8_t number_of_cached_bytes) {
    bool shouldFinalizeHash = ctx->number_of_atom_bytes_parsed + number_of_atom_bytes_received == ctx->atom_byte_count;

    PRINTF("Updating hash with #%d bytes\n", number_of_atom_bytes_received);

    if (shouldFinalizeHash) {
        PRINTF("\nFinalizing hash!\n\n");
    }


    // UPDATE HASH
    sha256_hash(
        &(ctx->hasher),
        /* bytes to hash */ ctx->atom_slice + number_of_cached_bytes,
        (size_t)number_of_atom_bytes_received,
        shouldFinalizeHash,
        ctx->hash);

    if (shouldFinalizeHash) {
        // re-initiate hasher
        cx_sha256_init(&(ctx->hasher));

        // tmp copy of firstHash
        uint8_t hashedOnce[HASH256_BYTE_COUNT];
        os_memcpy(hashedOnce, ctx->hash, HASH256_BYTE_COUNT);

        sha256_hash(
            &(ctx->hasher),
            hashedOnce,
            HASH256_BYTE_COUNT,
            true,
            ctx->hash // put hash of hash in ctx->hash
        );
    }
}

static bool is_meta_data_about_transferrable_tokens_particle() {
    assert(ctx->particle_meta_data.has_relevant_data);

    return (ctx->particle_meta_data.addressOfRecipientByteInterval.byteCount > 0) &&
        (ctx->particle_meta_data.amountByteInterval.byteCount > 0) &&
        (ctx->particle_meta_data.token_definition_referenceByteInterval.byteCount > 0);
}

typedef enum {
    ParticleFieldNoField = 0,
    ParticleFieldAddress,
    ParticleFieldAmount,
    ParticleFieldSerializer,
    ParticleFieldTokenDefinitionReference,
} ParticleField;

static CBORBytePrefixForByteArray cborBytePrefixForParticleField(ParticleField field)
{
    switch (field)
    {
    case ParticleFieldAddress:
    {
        return ByteStringCBORPrefixByte_address;
    }
    case ParticleFieldAmount:
    {
        return ByteStringCBORPrefixByte_uint256;
    }
    case ParticleFieldTokenDefinitionReference:
    {
        return ByteStringCBORPrefixByte_rri;
    }
    default:
        FATAL_ERROR("Unknown field: %d", field);
    }
}

static bool is_empty(unsigned char * buf, int size) {
    int i;
    for(i = 0; i < size; i++) {
        if(buf[i] != 0) return false;
    }
    return true;
}

static bool is_address_in_transfer_empty() {
    return is_empty(&ctx->transfer.address.bytes, RADIX_ADDRESS_BYTE_COUNT);
}

static bool is_amount_in_transfer_empty() {
    return is_empty(&ctx->transfer.amount.bytes, RADIX_AMOUNT_BYTE_COUNT);
}

static ParticleField next_field_to_parse() {

    if (!ctx->particle_meta_data.has_relevant_data) {
        return ParticleFieldNoField;
    }

    if (!is_meta_data_about_transferrable_tokens_particle())
    {
        return ParticleFieldSerializer;
    }

    if (is_address_in_transfer_empty()) {
        return ParticleFieldAddress;
    }

     if (is_amount_in_transfer_empty()) {
        return ParticleFieldAmount;
    }

    if (!ctx->transfer.has_confirmed_serializer)
    {
        return ParticleFieldSerializer;
    }

    return ParticleFieldTokenDefinitionReference;
}


// Returns `true` iff `utf8_string` indicates a TransferrableTokensParticle
static bool is_transferrable_tokens_particle_serializer(
    const char *utf8_string,
    const size_t string_length
) {
    return (strncmp(utf8_string, "radix.particles.transferrable_tokens", string_length) == 0);
}

// Returns `true` iff `cborValue` indicates a TransferrableTokensParticle
static bool parseSerializer_is_ttp(
    const size_t valueByteCount,
    CborValue *cborValue)
{
    size_t numberOfBytesReadByCBORParser = valueByteCount;
    char textString[valueByteCount]; 
    CborError cborError = cbor_value_copy_text_string(
        cborValue,
        textString,
        &numberOfBytesReadByCBORParser,
        NULL);

    if (cborError)
    {
        FATAL_ERROR("Error parsing 'serializer' field in atomSlice, CBOR eror: '%s'\n", cbor_error_string(cborError));
    }

    assert(numberOfBytesReadByCBORParser == valueByteCount);
    PRINTF("Parsed particle serializer: '%s'\n", textString);
    return is_transferrable_tokens_particle_serializer(textString, valueByteCount);
}


static void ask_user_for_confirmation_of_transfer_if_needed() {
    FATAL_ERROR("TODO ask user for confirmation of transfer");
}


static void parseParticleField(
    const size_t valueByteCount,
    CborValue *cborValue,
    ParticleField field,

    uint8_t *output_buffer
) {

    CBORBytePrefixForByteArray cborBytePrefix = cborBytePrefixForParticleField(field);

    size_t numberOfBytesReadByCBORParser = valueByteCount;
    uint8_t byteString[valueByteCount];
    CborError cborError = cbor_value_copy_byte_string(
        cborValue,
        byteString,
        &numberOfBytesReadByCBORParser,
        NULL);

    if (cborError)
    {
        FATAL_ERROR("Error parsing field in atomSlice, CBOR eror: '%s'\n", cbor_error_string(cborError));
    }

    // Sanity check
    assert(numberOfBytesReadByCBORParser == valueByteCount);
    assert(byteString[0] == cborBytePrefix);

    os_memcpy(
        output_buffer,
        byteString + 1, // Drop first CBOR prefix byte
        valueByteCount);
}

static size_t parse_particle_field_from_atom_slice(
    ParticleField type_of_field_to_parse,
    const size_t field_position_in_atom_slice,
    const size_t field_byte_count
) {

    CborParser cborParser;
    CborValue cborValue;
    CborError cborError = cbor_parser_init(
        ctx->atom_slice + field_position_in_atom_slice,
        field_byte_count,
        0, // flags
        &cborParser,
        &cborValue);

    if (cborError)
    {
        FATAL_ERROR("Failed to init cbor parser, CBOR eror: '%s'\n", cbor_error_string(cborError));
    }

    CborType type = cbor_value_get_type(&cborValue);
    size_t readLength;
    cborError = cbor_value_calculate_string_length(&cborValue, &readLength);

    if (cborError)
    {
        FATAL_ERROR("Failed to calculate length of coming cbor value, CBOR eror: '%s'\n", cbor_error_string(cborError));
    }

    switch (type_of_field_to_parse)
    {
        case ParticleFieldNoField: 
        FATAL_ERROR("Incorrect impl");
        break;

    case ParticleFieldAddress:
        assert(type == CborByteStringType);

        parseParticleField(
            readLength, 
            &cborValue, 
            ParticleFieldAddress, 
            ctx->transfer.address.bytes
        );
        
        assert(!is_address_in_transfer_empty())
        PRINTF("Parsed address: "); printRadixAddress(&ctx->transfer.address);
        break;

    case ParticleFieldAmount:
        assert(type == CborByteStringType);
        assert(!is_address_in_transfer_empty())

        parseParticleField(
            readLength, 
            &cborValue, 
            ParticleFieldAmount, 
            ctx->transfer.amount.bytes
        );
        PRINTF("Parsed amount: "); printTokenAmount(&ctx->transfer.amount);
        break;

    case ParticleFieldSerializer:
        assert(type == CborTextStringType);
        assert(!ctx->transfer.has_confirmed_serializer);
        
        bool is_transferrable_tokens_particle_serializer = parseSerializer_is_ttp(readLength, &cborValue);

        if (!is_transferrable_tokens_particle_serializer) {
            assert(is_address_in_transfer_empty());
            assert(is_amount_in_transfer_empty());
            ctx->non_transfer_data_found = true;
        } else {
            assert(!is_address_in_transfer_empty());
            assert(!is_amount_in_transfer_empty());
            ctx->transfer.has_confirmed_serializer = true;
        }

        break;

    case ParticleFieldTokenDefinitionReference:
        assert(type == CborByteStringType);
        assert(ctx->transfer.has_confirmed_serializer);
        
        parseParticleField(
            readLength, 
            &cborValue, 
            ParticleFieldTokenDefinitionReference, 
            ctx->transfer.token_definition_reference.bytes
        );
        
        PRINTF("Parsed RRI: "); printRRI(&ctx->transfer.token_definition_reference);

        ask_user_for_confirmation_of_transfer_if_needed();

        break;
    }

    return readLength;
}

static ByteInterval next_byte_interval(
    ParticleField type_of_field_to_parse
) {
    switch (type_of_field_to_parse)
    {
    case ParticleFieldNoField:
        FATAL_ERROR("Incorrect impl");
    case ParticleFieldAddress:
        return ctx->particle_meta_data.addressOfRecipientByteInterval;
    case ParticleFieldAmount:
        return ctx->particle_meta_data.amountByteInterval;
    case ParticleFieldSerializer:
        return ctx->particle_meta_data.serializerValueByteInterval;
    case ParticleFieldTokenDefinitionReference:
        return ctx->particle_meta_data.token_definition_referenceByteInterval;
    }
}

static void cache_bytes_to_next_chunk(
    const size_t field_position_in_atom_slice,
    const size_t number_of_bytes_to_cache
) {
    assert(number_of_bytes_to_cache <= MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS);
    uint8_t tmp[number_of_bytes_to_cache];

    os_memcpy(
        tmp,
        ctx->atom_slice + field_position_in_atom_slice,
        number_of_bytes_to_cache);

    empty_atom_slice();

    os_memcpy(
        ctx->atom_slice,
        tmp,
        number_of_bytes_to_cache);

    ctx->number_of_cached_bytes = number_of_bytes_to_cache;
}

// returns `true` iff we are done with the current atom slice
static bool parse_particle_field_if_needed(
    uint8_t number_of_cached_bytes,
    size_t chunk_start_position_in_atom,
    size_t number_of_new_bytes
) {
    
    ParticleField type_of_field_to_parse = next_field_to_parse();

    if (type_of_field_to_parse == ParticleFieldNoField) {
        PRINTF("Skipping parsing of particle field since we dont have any ParticleMetaData...\n");
        return true;
    }

    size_t chunk_end_position_in_atom = chunk_start_position_in_atom + number_of_new_bytes;


    ByteInterval field_byte_interval = next_byte_interval(type_of_field_to_parse);

    size_t field_start_position_in_atom = field_byte_interval.startsAt;
    size_t field_byte_count = field_byte_interval.byteCount;
    size_t field_end_position_in_atom = field_start_position_in_atom + field_byte_count;

    bool can_parse_next_field = field_end_position_in_atom <= chunk_end_position_in_atom;

    size_t field_position_in_atom_slice = number_of_cached_bytes + field_start_position_in_atom - chunk_start_position_in_atom;

        PRINTF("\n\n#######################################\n\n");
        PRINTF("number_of_cached_bytes: %d\n", number_of_cached_bytes);
        PRINTF("chunk_start_position_in_atom: %d\n", chunk_start_position_in_atom);
        PRINTF("number_of_new_bytes: %d\n", number_of_new_bytes);
        PRINTF("type_of_field_to_parse: %d\n", type_of_field_to_parse);
        PRINTF("chunk_end_position_in_atom: %d\n", chunk_end_position_in_atom);
        PRINTF("field_start_position_in_atom: %d\n", field_start_position_in_atom);
        PRINTF("field_byte_count: %d\n", field_byte_count);
        PRINTF("field_end_position_in_atom: %d\n", field_end_position_in_atom);
        PRINTF("can_parse_next_field: %s\n", can_parse_next_field ? "TRUE" : "FALSE");
        PRINTF("field_position_in_atom_slice: %d\n", field_position_in_atom_slice);

    if (!can_parse_next_field) {

        bool needs_to_cache_bytes = (field_start_position_in_atom < chunk_end_position_in_atom);

        PRINTF("needs_to_cache_bytes: %s\n", needs_to_cache_bytes ? "TRUE" : "FALSE");

        if (needs_to_cache_bytes)
        {
            size_t number_of_bytes_to_cache = chunk_end_position_in_atom - field_start_position_in_atom;
            cache_bytes_to_next_chunk(field_position_in_atom_slice, number_of_bytes_to_cache);
        }

        return true;
    }
    

    PRINTF("Parsing particle contents in atom between these bytes: [%d - %d]\n", field_start_position_in_atom, field_end_position_in_atom);
    parse_particle_field_from_atom_slice(
        type_of_field_to_parse,
        field_position_in_atom_slice,
        field_byte_count
    );

    return false;
}


static void hash_and_parse_atom_bytes(uint8_t number_of_atom_bytes_received) {
    uint8_t number_of_cached_bytes = ctx->number_of_cached_bytes;
    ctx->number_of_cached_bytes = 0;
    update_hash(number_of_atom_bytes_received, number_of_cached_bytes);

    bool done_with_atom_bytes = false;
    int counter = 0;
    while (!done_with_atom_bytes) {
        PRINTF("hash_and_parse_atom_bytes - loop counter=%d\n", counter);
        done_with_atom_bytes = parse_particle_field_if_needed(
            number_of_cached_bytes,
            ctx->number_of_atom_bytes_parsed,
            number_of_atom_bytes_received
        );
        counter++;
    }

    ctx->number_of_atom_bytes_parsed += number_of_atom_bytes_received;
}

static void parse_bytes_from_host_machine() {

    uint8_t atom_bytes_received = receive_bytes_from_host_machine();

    if (atom_bytes_received) {
        hash_and_parse_atom_bytes(atom_bytes_received);
    } else {
        PRINTF("Got particle meta data\n");
    }
}

static void parse_atom() {
    while (ctx->number_of_atom_bytes_parsed < ctx->atom_byte_count) {
        parse_bytes_from_host_machine();
    }
    PRINTF("Finished parsing all atom bytes.\n");
}

static void parse_and_sign_atom(
    const uint8_t number_of_up_particles,
    uint8_t *dataBuffer,
    const uint16_t dataLength
) {
	initiate_state();
    ctx->number_of_up_particles = number_of_up_particles;
	parse_bip_and_atom_size(dataBuffer, dataLength);
    
    parse_atom();
}

void handleSignAtom(
    uint8_t p1,
    uint8_t p2,
    uint8_t *dataBuffer,
    uint16_t dataLength,
    volatile unsigned int *flags,
    volatile unsigned int *tx)
{
    parse_and_sign_atom(
        p1,
        dataBuffer,
        dataLength
    );

    *flags |= IO_ASYNCH_REPLY;
}