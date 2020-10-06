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
    ctx->particle_meta_data.is_initialized = false;
}

static void empty_transfer() {
    explicit_bzero(&ctx->transfer, sizeof(Transfer));
    ctx->transfer.has_confirmed_serializer = false;
    ctx->transfer.is_address_set = false;
    ctx->transfer.is_amount_set = false;
    ctx->transfer.is_token_definition_reference_set = false;
}

static void empty_atom_slice() {
    explicit_bzero(&ctx->atom_slice, MAX_ATOM_SLICE_SIZE);
}

static void reset_state() {
    ctx->atom_byte_count = 0;
    ctx->number_of_atom_bytes_received = 0;
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
    assert(dataLength == 20);
    
    // PRINTF("Received meta data about: #%u particles\n", ctx->numberOfParticlesWithSpinUp);
    PRINTF("Received particle meta data hex string:\n%.*H\n", dataLength, dataBuffer);
    int dataOffset = 0;

    PRINTF("Zeroing out old particle meta data now...\n");
    empty_particle_meta_data();

    ctx->particle_meta_data.particleItself.startsAt = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    ctx->particle_meta_data.particleItself.byteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

    ctx->particle_meta_data.addressOfRecipientByteInterval.startsAt = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    ctx->particle_meta_data.addressOfRecipientByteInterval.byteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

    ctx->particle_meta_data.amountByteInterval.startsAt = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    ctx->particle_meta_data.amountByteInterval.byteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

    ctx->particle_meta_data.serializerValueByteInterval.startsAt = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    ctx->particle_meta_data.serializerValueByteInterval.byteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

    ctx->particle_meta_data.token_definition_referenceByteInterval.startsAt = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    ctx->particle_meta_data.token_definition_referenceByteInterval.byteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

    PRINTF("\nFinished parsing particle meta data...\n\n");

    ctx->particle_meta_data.is_initialized = true;
}

static void update_hash(uint8_t* bytes, uint16_t byte_count, bool should_finalize_hash) {

    PRINTF("Updating hash with #%d bytes\n", byte_count);

    // UPDATE HASH
    sha256_hash(
        &(ctx->hasher),
        bytes,
        byte_count,
        should_finalize_hash,
        ctx->hash);

    if (should_finalize_hash) {
          PRINTF("\nFinalizing hash!\n\n");
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


/// If we just received a new ParticleMetaData this functions returns `0`, otherwise it returns the number of newly
/// recived atom bytes (i.e. bytes that needs to be use to update hash and possibly be parsed)
static uint8_t receive_bytes_from_host_machine_and_update_hash() {
    empty_buffer();
    G_io_apdu_buffer[0] = 0x90; // 0x9000 == 'SW_OK'
    G_io_apdu_buffer[1] = 0x00; // 0x9000 == 'SW_OK'
    io_exchange(CHANNEL_APDU, 2);

    uint8_t p1 = G_io_apdu_buffer[OFFSET_P1];
    uint8_t p2 = G_io_apdu_buffer[OFFSET_P2];
    uint8_t* dataBuffer = G_io_apdu_buffer + OFFSET_CDATA;
    uint16_t number_of_atom_bytes_newly_received = G_io_apdu_buffer[OFFSET_LC];

    PayloadType payloadType = p1;

    switch (payloadType)
    {
    case PayloadTypeIsAtomBytes:
        ctx->number_of_atom_bytes_received += number_of_atom_bytes_newly_received;

        // Update hash
        bool should_finalize_hash = ctx->number_of_atom_bytes_received == ctx->atom_byte_count;

        update_hash(
            dataBuffer,
            number_of_atom_bytes_newly_received,
            should_finalize_hash
        );

        os_memcpy(
            ctx->atom_slice + ctx->number_of_cached_bytes,
            dataBuffer,
            number_of_atom_bytes_newly_received
        );
        return number_of_atom_bytes_newly_received;
    case PayloadTypeIsParticleMetaData:
        parse_particle_meta_data(dataBuffer, number_of_atom_bytes_newly_received);
        return 0; // Meta Data about Particle is not atom bytes, should not update hash with these
    default:
        FATAL_ERROR("Unrecognized P1 value: %d\n", p1)
    }
}

static bool is_meta_data_about_transferrable_tokens_particle() {
    assert(ctx->particle_meta_data.is_initialized);

    return (ctx->particle_meta_data.addressOfRecipientByteInterval.byteCount > 0) &&
        (ctx->particle_meta_data.amountByteInterval.byteCount > 0) &&
        (ctx->particle_meta_data.token_definition_referenceByteInterval.byteCount > 0);
}

typedef enum {
    ParticleFieldNoField = 0,
    ParticleFieldAddress = 1,
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

// static ParticleField next_field_to_parse() {

//     if (!ctx->particle_meta_data.is_initialized) {
//         FATAL_ERROR("No particle meta data");
//     }

//     if (!is_meta_data_about_transferrable_tokens_particle())
//     {
//         PRINTF("Next field: 'Serializer' (since non TTP)\n");
//         return ParticleFieldSerializer;
//     }

//     if (!ctx->transfer.is_address_set) {
//         PRINTF("Next field: 'Address'\n");
//         return ParticleFieldAddress;
//     }

//     if (!ctx->transfer.is_amount_set) {
//         PRINTF("Next field: 'Amount'\n");
//         return ParticleFieldAmount;
//     }

//     if (!ctx->transfer.has_confirmed_serializer)
//     {
//         PRINTF("Next field: 'Serializer' (since not confirmed it for current TTP)\n");
//         return ParticleFieldSerializer;
//     }

//     PRINTF("Next field: 'TokenDefinitionReference'\n");
//     assert(!ctx->transfer.is_token_definition_reference_set)
//     return ParticleFieldTokenDefinitionReference;
// }


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

// static ByteInterval next_byte_interval(
//     ParticleField type_of_field_to_parse
// ) {
//     switch (type_of_field_to_parse)
//     {
//     case ParticleFieldAddress:
//         return ctx->particle_meta_data.addressOfRecipientByteInterval;
//     case ParticleFieldAmount:
//         return ctx->particle_meta_data.amountByteInterval;
//     case ParticleFieldSerializer:
//         return ctx->particle_meta_data.serializerValueByteInterval;
//     case ParticleFieldTokenDefinitionReference:
//         return ctx->particle_meta_data.token_definition_referenceByteInterval;
//     }
// }

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


static void parse_particle_field_from_atom_slice(
    ParticleField type_of_field_to_parse,
    uint8_t *bytes,
    const size_t field_byte_count
) {

    CborParser cborParser;
    CborValue cborValue;
    CborError cborError = cbor_parser_init(
        bytes,
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
        assert(!ctx->transfer.is_address_set);

        parseParticleField(
            readLength, 
            &cborValue, 
            ParticleFieldAddress, 
            ctx->transfer.address.bytes
        );
        
        ctx->transfer.is_address_set = true;
        PRINTF("Parsed address: "); printRadixAddress(&ctx->transfer.address);
        break;

    case ParticleFieldAmount:
        assert(type == CborByteStringType);
        assert(ctx->transfer.is_address_set);
        assert(!ctx->transfer.is_amount_set);

        parseParticleField(
            readLength, 
            &cborValue, 
            ParticleFieldAmount, 
            ctx->transfer.amount.bytes
        );
        ctx->transfer.is_amount_set = true;
        PRINTF("Parsed amount: "); printTokenAmount(&ctx->transfer.amount);
        break;

    case ParticleFieldSerializer:
        assert(type == CborTextStringType);
        assert(!ctx->transfer.has_confirmed_serializer);
        
        bool is_transferrable_tokens_particle_serializer = parseSerializer_is_ttp(readLength, &cborValue);

        assert(ctx->transfer.is_address_set == is_transferrable_tokens_particle_serializer);
        assert(ctx->transfer.is_amount_set == is_transferrable_tokens_particle_serializer);

        if (!is_transferrable_tokens_particle_serializer) {
            ctx->non_transfer_data_found = true;
        } else {
            ctx->transfer.has_confirmed_serializer = true;
        }

        break;

    case ParticleFieldTokenDefinitionReference:
        assert(type == CborByteStringType);
        assert(ctx->transfer.has_confirmed_serializer);
        assert(ctx->transfer.is_address_set);
        assert(ctx->transfer.is_amount_set);
        assert(!ctx->transfer.is_token_definition_reference_set);
        
        parseParticleField(
            readLength, 
            &cborValue, 
            ParticleFieldTokenDefinitionReference, 
            ctx->transfer.token_definition_reference.bytes
        );

        ctx->transfer.is_token_definition_reference_set = true;
        
        PRINTF("Parsed RRI: "); printRRI(&ctx->transfer.token_definition_reference);


        ask_user_for_confirmation_of_transfer_if_needed();
        FATAL_ERROR("MUST BLOCK here so we empty transfer after user has");
        empty_transfer();

        break;
    }

    // return readLength;
}

static int number_of_overlapping_bytes_in_intervals(
    ByteInterval a,
    ByteInterval b
) {
	return MAX(
		0, 
        MIN(end_index(a), end_index(b)) - MAX(a.startsAt, b.startsAt)
	);
}

static bool atom_slice_contains_particles_bytes() {
    assert(ctx->particle_meta_data.is_initialized);
   return number_of_overlapping_bytes_in_intervals(
       ctx->interval_of_atom_slice,
       ctx->particle_meta_data.particleItself
   ) > 0;
}

// Returns true if there is a next interval to parse (populated in input param)
static bool next_field_to_parse_and_update_atom_slice(ByteInterval* interval, ByteInterval* output, bool *is_done_with_slice) {
        if (interval->byteCount == 0) {
            return false;
        }

        FATAL_ERROR("impl me");

		// 	guard currentAtomSlice.endsWith >= interval.endsWith else {
		// 		print("`currentAtomSlice.endsWith < interval.endsWith` => caching bytes!")
		// 		ctx.noCachedBytes = currentAtomSlice.byteCount
		// 		doneWithAtomSlice = true
		// 		return nil
		// 	}

		// 	guard 
		// 		currentAtomSlice.startsAt <= interval.startsAt
		// 	else {
		// 		print("interval not in atom slice, maybe another interval for the same particle? SHOULD WE UPDATE currentAtomSlice.startsAt???")
		// 		return nil
		// 	}

		// 	if currentAtomSlice.startsAt != interval.startsAt {
		// 		print("`currentAtomSlice.startsAt != interval.startsAt` => setting `currentAtomSlice.startsAt := interval.startsAt` and decreasing `currentAtomSlice.byteCount`")
		// 		currentAtomSlice.byteCount -= (interval.startsAt - currentAtomSlice.startsAt)
		// 		currentAtomSlice.startsAt = interval.startsAt
		// 	}
		
		// 	assert(currentAtomSlice.byteCount >= interval.byteCount)
		// 	return interval
		// }
}

// Returns true if there is a next interval to parse (populated in input param)
static bool get_interval_of_next_field_to_parse(ParticleField *field_type, ByteInterval *next_field) {
	assert(ctx->particle_meta_data.is_initialized);

    bool is_done_with_slice = false;
	
    *field_type = ParticleFieldNoField;

    if (
        next_field_to_parse_and_update_atom_slice(
            &ctx->particle_meta_data.addressOfRecipientByteInterval, 
            next_field,
            &is_done_with_slice
        )
    ) {
        *field_type = ParticleFieldAddress;
        return true;
    }

    if (
        next_field_to_parse_and_update_atom_slice(
            &ctx->particle_meta_data.amountByteInterval,
            next_field,
            &is_done_with_slice
        )
    ) {
        *field_type = ParticleFieldAmount;
        return true;
    }

    if (
        next_field_to_parse_and_update_atom_slice(
            &ctx->particle_meta_data.serializerValueByteInterval,
            next_field,
            &is_done_with_slice
        )
    ) {
        *field_type = ParticleFieldSerializer;
        return true;
    }

    if (
        next_field_to_parse_and_update_atom_slice(
            &ctx->particle_meta_data.token_definition_referenceByteInterval,
            next_field,
            &is_done_with_slice
        )
    ) {
        *field_type = ParticleFieldTokenDefinitionReference;
        return true;
    }
	
    PRINTF("No next particle field in current atom slice to parse...");
    return false;
}
	

static void parse_bytes_from_host_machine() {
    
    uint8_t number_of_newly_received_bytes = receive_bytes_from_host_machine_and_update_hash();

    if (number_of_newly_received_bytes) {
        // Parse newly received Atom bytes if able/needed

        if (!ctx->particle_meta_data.is_initialized) {
            PRINTF("Skipping parsing atom bytes since we have no particle meta data");
        	return;
        }

        uint8_t number_of_cached_bytes = ctx->number_of_cached_bytes;
        ctx->number_of_cached_bytes = 0;

        ctx->interval_of_atom_slice = (ByteInterval) { 
            .startsAt = ctx->number_of_atom_bytes_received - number_of_cached_bytes,
            .byteCount = number_of_cached_bytes + number_of_newly_received_bytes
        };

        int counter_DEBUG_ONLY = 0;

        ByteInterval interval_of_next_field_to_parse;
        ParticleField particle_field_type;
        while (atom_slice_contains_particles_bytes()) { // will "slide" atom slice window
            PRINTF("parse_atom_bytes (ITERATION=%d)\n", counter_DEBUG_ONLY);

            if (
                !get_interval_of_next_field_to_parse(
                    &interval_of_next_field_to_parse, 
                    &particle_field_type
                )
            ) {
                return;
            }

            uint16_t start_position_of_field_in_slice = interval_of_next_field_to_parse.startsAt - ctx->interval_of_atom_slice.startsAt;

            PRINTF("start_position_of_field_in_slice: %d\n", start_position_of_field_in_slice);

            parse_particle_field_from_atom_slice(
                particle_field_type,
                ctx->atom_slice + start_position_of_field_in_slice,
                interval_of_next_field_to_parse.byteCount
            );

            counter_DEBUG_ONLY += 1;
        }

    } else {
        assert(ctx->particle_meta_data.is_initialized);
        PRINTF("Just got a new particle meta data, nothing to do.\n");
    }
}

static void parse_atom() {
    while (ctx->number_of_atom_bytes_parsed < ctx->atom_byte_count) {
        parse_bytes_from_host_machine();
    }
    PRINTF("Finished parsing all atom bytes => Asking user to confirm hash on Ledger...\n");
    askUserForConfirmationOfHash();
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
