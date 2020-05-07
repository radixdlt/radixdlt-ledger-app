#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "radix.h"
#include "ux.h"
#include "sha256_hash.h"
#include "cbor.h"
#include "RadixAddress.h"
#include "RadixResourceIdentifier.h"
#include "TokenAmount.h"

// Get a pointer to signHash's state variables. This is purely for
// convenience, so that we can refer to these variables concisely from any
// signHash-related function.
static signAtomContext_t *ctx = &global.signAtomContext;

static bool isZeroByteInterval(ByteInterval *byteInterval) {
	if (byteInterval->byteCount > 0) {
		return false;
	}
	assert(byteInterval->startsAt == 0);
	return true;
}

static bool isMetaDataForTransferrableTokensParticle(ParticleMetaData *particleMetaData) {
	if (isZeroByteInterval(&particleMetaData->addressOfRecipientByteInterval)) {
		assert(isZeroByteInterval(&particleMetaData->amountByteInterval));
		assert(isZeroByteInterval(&particleMetaData->tokenDefinitionReferenceByteInterval));
		return false;
	}
	return true;
}

// ☢️ NOT IMPL YET
// TODO IMPL ME, code below is just Wild-Guess-Draft
static void readNextChunkFromHostMachineAndUpdateHash(
    size_t chunkSize
) {
    G_io_apdu_buffer[0] = 0x90;
    G_io_apdu_buffer[1] = 0x00;
	unsigned rx = io_exchange(CHANNEL_APDU, 2);
	PRINTF("readNextChunkFromHostMachine: io_exchanged %d bytes\n", rx);
    // N.B. we do not provide any meta data at all for chunked data,
    // not in the databuffer any way, we might use P1, P2 here...
	uint32_t dataOffset = OFFSET_CDATA + 0;

    os_memcpy(
        /* destination */ ctx->atomSlice + ctx->numberOfCachedBytes, 
        /* source */ G_io_apdu_buffer + dataOffset, 
        /* number of bytes*/ chunkSize
    );

    bool shouldFinalizeHash = chunkSize < MAX_CHUNK_SIZE;

    // UPDATE HASH
    sha256_hash(
        &(ctx->hasher),
        /* bytes to hash */ ctx->atomSlice + ctx->numberOfCachedBytes,
        (size_t)chunkSize,
        shouldFinalizeHash,
        (shouldFinalizeHash ? ctx->hash : NULL)
    );
}

static RadixParticleTypes particleTypeFromUTF8String(
    const char *utf8_string,
    const size_t string_length
) {

    if (strncmp(utf8_string, "radix.particles.message", string_length) == 0) {
        return MessageParticleType;
    } else if (strncmp(utf8_string, "radix.particles.rri", string_length) == 0) {
        return RRIParticleType;
    } else if (strncmp(utf8_string, "radix.particles.fixed_supply_token_definition", string_length) == 0) {
        return FixedSupplyTokenDefinitionParticleType;
    } else if (strncmp(utf8_string, "radix.particles.mutable_supply_token_definition", string_length) == 0) {
        return MutableSupplyTokenDefinitionParticleType;
    } else if (strncmp(utf8_string, "radix.particles.unallocated_tokens", string_length) == 0) {
        return UnallocatedTokensParticleType;
    } else if (strncmp(utf8_string, "radix.particles.transferrable_tokens", string_length) == 0) {
        return TransferrableTokensParticleType;
    } else if (strncmp(utf8_string, "radix.particles.unique", string_length) == 0) {
        return UniqueParticleType;
    } else {
        return ParticleType_is_unknown;
    }
}

// static ByteIntervalField nextByteIntervalField(
//     const size_t numberOfBytesInAtomSliceParse,
//     const size_t sizeOfAtomSlice,
//     ByteInterval *output_next_byte_interval
// ) {
//     ParticleMetaData *particleMetaData = ctx->metaDataAboutParticles[ctx->numberOfParticlesParsed];
    
// }

// Please see column "Additional info" in table "CBOR Major types": https://radixdlt.atlassian.net/wiki/spaces/AM/pages/56557727/DSON+Encoding
typedef enum {
    // ByteStringCBORPrefixByte_bytes      = 1,
    // ByteStringCBORPrefixByte_euid       = 2,
    // ByteStringCBORPrefixByte_hash       = 3,
    ByteStringCBORPrefixByte_address    = 4,

    // Used for `amount`
    ByteStringCBORPrefixByte_uint256    = 5,

    // Used for `tokenDefinitionReference`
    ByteStringCBORPrefixByte_rri        = 6
    // ByteStringCBORPrefixByte_aid        = 8
} CBORBytePrefixForByteArray;


static void getNextByteInterval(
    ByteInterval *output_byteInterval
) {
    ParticleMetaData particleMetaData = ctx->metaDataAboutParticles[ctx->numberOfParticlesParsed];
    switch (ctx->nextFieldInParticleToParse) {
        case AddressByteIntervalField: 
            *output_byteInterval = particleMetaData.addressOfRecipientByteInterval;
            break;
        case AmountByteIntervalField: 
            *output_byteInterval = particleMetaData.amountByteInterval;
            break;
        case SerializerByteIntervalField: 
            *output_byteInterval = particleMetaData.serializerValueByteInterval;
            break;
        case TokenDefinitionReferenceByteIntervalField: 
            *output_byteInterval = particleMetaData.tokenDefinitionReferenceByteInterval;
            break;
    }
}

static void emptyAtomSlice() {
    os_memset(ctx->atomSlice, 0, MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS + MAX_CHUNK_SIZE);
}

// Returns a boolean value indicating whether or not all `ctx->atomByteCount` bytes
// have been parsed, i.e. the whole atom has been parsed.
static bool parseParticlesAndUpdateHash() {
    uint16_t bytesLeftToRead = ctx->atomByteCount - ctx->atomByteCountParsed;
	uint16_t chunkSize = MIN(MAX_CHUNK_SIZE, bytesLeftToRead);

    readNextChunkFromHostMachineAndUpdateHash((size_t)chunkSize);
    size_t numberOfCachedBytes = ctx->numberOfCachedBytes;
    ctx->numberOfCachedBytes = 0;
    size_t atomSliceByteCount = chunkSize + numberOfCachedBytes;
    size_t atomByteCountParsedBeforeThisChunk = ctx->atomByteCountParsed;
    ctx->atomByteCountParsed = atomByteCountParsedBeforeThisChunk + chunkSize;

    while (true) { // parse particles and their values
        ByteInterval *fieldByteInterval;
        getNextByteInterval(fieldByteInterval);
        
        size_t fieldByteCount = fieldByteInterval->byteCount;
        size_t fieldPositionInAtom = fieldByteInterval->startsAt;

        FAIL("TODO: Confirm calculation of 'fieldPositionInAtomSlice' below");
        size_t fieldPositionInAtomSlice = fieldPositionInAtom - atomByteCountParsedBeforeThisChunk + numberOfCachedBytes; 

        // OK we cannot parse next field since it spans across next chunk => Cache bytes if needed
        if (fieldPositionInAtomSlice + fieldByteCount > atomSliceByteCount) {
            size_t numberOfBytesToCache = atomSliceByteCount - fieldByteCount;

            uint8_t tmp[numberOfBytesToCache]; // uint8_t tmp[MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS];

            os_memcpy(
                tmp, 
                ctx->atomSlice + fieldPositionInAtomSlice,
                numberOfBytesToCache
            );

            emptyAtomSlice();
            
            os_memcpy(
                ctx->atomSlice, 
                tmp,
                numberOfBytesToCache
            );

            ctx->numberOfCachedBytes = numberOfBytesToCache;
            ctx->atomByteCountParsed -= numberOfBytesToCache;

            return false;
        }

        CborParser cborParser;
        CborValue cborValue;
        CborError cborError = cbor_parser_init(
            ctx->atomSlice + fieldPositionInAtomSlice, 
            fieldByteCount, // might not be whole particle
            0, // flags
            &cborParser,
            &cborValue
        );
        if (cborError) {
            FATAL_ERROR("Failed to init cbor parser, CBOR eror: '%s'\n", cbor_error_string(cborError)); 
        }

        CborType type = cbor_value_get_type(&cborValue);
        size_t readLength;
        cborError = cbor_value_calculate_string_length(&cborValue, &readLength);
        if (cborError) {
            FATAL_ERROR("Failed to calculate length of coming cbor value, CBOR eror: '%s'\n", cbor_error_string(cborError)); 
        }

        if (readLength != fieldByteCount) {
            FATAL_ERROR("Read CBOR string length and expected field byte count differs.");
        }

        char textOrByteString[fieldByteCount];

        switch (ctx->nextFieldInParticleToParse) {
            case AddressByteIntervalField: 
                if (type != CborByteStringType) {
                    FATAL_ERROR("Inconsistency, internal state expects to read 'address' field (cbor type 'byte string', prefixed with: 0x%d), but got other CBOR major type.", ByteStringCBORPrefixByte_address);
                }

                cborError = cbor_value_copy_byte_string(
                    &cborValue, 
                    textOrByteString, 
                    &fieldByteCount, 
                    NULL
                );

                if (cborError) {
                    FATAL_ERROR("Error parsing 'address' field in atomSlice, CBOR eror: '%s'\n", cbor_error_string(cborError)); // will terminate app
                }

                if ((uint8_t)(textOrByteString[0]) != ByteStringCBORPrefixByte_address) {
                    FATAL_ERROR("Expected to see first byte with value %u, indicating that this byte string is an address, but got: %u", ByteStringCBORPrefixByte_address, (uint8_t)(textOrByteString[0]));
                }

                RadixAddress address;
                from_cbor_to_RadixAddress(
                    // Drop first byte, since it only specifies the `address` type.
                    textOrByteString + 1,
                    fieldByteCount - 1,
                    &address
                );

                break;
            case AmountByteIntervalField: 
                if (type != CborByteStringType) {
                    FATAL_ERROR("Inconsistency, internal state expects to read 'amount' field (cbor type 'byte string', prefixed with: 0x%d), but got other CBOR major type.", ByteStringCBORPrefixByte_uint256);
                }
                ctx->needsToConfirmThatNextSerializerIsTransferrableTokensParticle = true;
                break;
            case SerializerByteIntervalField: 
                if (type != CborTextStringType) {
                    FATAL_ERROR("Inconsistency, internal state expects to read 'serializer' field (cbor type 'text/utf8 string'), but got other CBOR major type.");
                }

                cborError = cbor_value_copy_text_string(
                    &cborValue,
                    textOrByteString,
                    &fieldByteCount,
                    NULL
                );

                if (cborError) {
                    FATAL_ERROR("Error parsing 'serializer' field in atomSlice, CBOR eror: '%s'\n", cbor_error_string(cborError)); // will terminate app
                }

                RadixParticleTypes particleType = particleTypeFromUTF8String(textOrByteString, fieldByteCount);
                if (ctx->needsToConfirmThatNextSerializerIsTransferrableTokensParticle) {
                    if (particleType != TransferrableTokensParticleType) {
                        FATAL_ERROR("Incorrect particle type, expected `TransferrableTokensParticle`, but got other.");
                    }
                    ctx->needsToConfirmThatNextSerializerIsTransferrableTokensParticle = false;
                }
                ctx->identifiedParticleTypesInAtom[ctx->numberOfParticlesParsed] = particleType;

                break;
            case TokenDefinitionReferenceByteIntervalField: 
                if (type != CborByteStringType) {
                    FATAL_ERROR("Inconsistency, internal state expects to read 'tokenDefinitionReference' field (cbor type 'byte string', prefixed with: 0x%d), but got other CBOR major type.", ByteStringCBORPrefixByte_rri);
                }
                break;
        }

        ctx->nextFieldInParticleToParse++;
        if (ctx->nextFieldInParticleToParse == AddressByteIntervalField) {
            ctx->numberOfParticlesParsed++;
        }
    }

    return ctx->numberOfParticlesParsed >= ctx->numberOfParticlesWithSpinUp;
}

static void parseAtom() {

    while(!parseParticlesAndUpdateHash()) {
        PRINTF("Finished parsing %u/%u particles", ctx->numberOfParticlesParsed, ctx->numberOfParticlesWithSpinUp);
        PRINTF("Finished parsing %u/%u bytes of the Atom", ctx->atomByteCountParsed, ctx->atomByteCount);
    }
}

// p1 = #particlesWithSpinUp
// p2 = NOT USED
// dataBuffer:
//          12 bytes: BIP32 PATH
//          2 bytes:  Atom Byte Count (CBOR encoded)
//          4-240 bytes: `P1` many offsets to particles à 4 bytes.
void handleSignAtom(
    uint8_t p1, 
    uint8_t p2, 
    uint8_t *dataBuffer, 
    uint16_t dataLength, 
    volatile unsigned int *flags, 
    volatile unsigned int *tx
) {
    // INPUT VALIDATION
    uint16_t expected_number_of_bip32_compents = 3;
    uint16_t byte_count_bip_component = 4;
    uint16_t expected_bip32_byte_count = expected_number_of_bip32_compents * byte_count_bip_component;
    
    if (dataLength < expected_bip32_byte_count) {
        PRINTF("'dataLength' should be at least: %u, but was: %d\n", expected_bip32_byte_count, dataLength);
        THROW(SW_INVALID_PARAM);
    }

    ctx->numberOfParticlesWithSpinUp = p1;
    if (ctx->numberOfParticlesWithSpinUp > MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP || ctx->numberOfParticlesWithSpinUp < 1) {
        PRINTF("Number of particles with spin up must be at least 1 and cannot exceed: %d, but got: %d\n", MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP, ctx->numberOfParticlesWithSpinUp);
        THROW(SW_INVALID_PARAM);
    }
 
    // PARSE DATA
    int dataOffset = 0;

    // READ BIP32 path from first chunk, available directly
    parse_bip32_path_from_apdu_command(dataBuffer, ctx->bip32Path, ctx->bip32PathString, sizeof(ctx->bip32PathString)); dataOffset += expected_bip32_byte_count;
    PRINTF("BIP 32 Path used for signing: %s\n", ctx->bip32PathString);

    // READ Atom Byte Count (CBOR encoded data)
    ctx->atomByteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    ctx->atomByteCountParsed = 0;

    // READ meta data about particles from first chunk, available directly
    ctx->numberOfParticlesParsed = 0;
    for (uint8_t particleIndex = 0; particleIndex < ctx->numberOfParticlesWithSpinUp; ++particleIndex) {
        // In this (alphabetical) order: [address, amount, serializer, tokenDefRef]
        // read the values.

        uint16_t addressOfRecipientByteIntervalStart = U2BE(dataBuffer, dataOffset); dataOffset += 2;
		uint16_t addressOfRecipientByteIntervalCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

        ByteInterval addressOfRecipientByteInterval = { 
            .startsAt = addressOfRecipientByteIntervalStart,
            .byteCount = addressOfRecipientByteIntervalCount
        };

        uint16_t amountByteIntervalStart = U2BE(dataBuffer, dataOffset); dataOffset += 2;
		uint16_t amountByteIntervalCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

        ByteInterval amountByteInterval = { 
            .startsAt = amountByteIntervalStart,
            .byteCount = amountByteIntervalCount
        };

        uint16_t serializerByteIntervalStart = U2BE(dataBuffer, dataOffset); dataOffset += 2;
		uint16_t serializerByteIntervalCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

        ByteInterval serializerValueByteInterval = { 
            .startsAt = serializerByteIntervalStart,
            .byteCount = serializerByteIntervalCount
        };

        uint16_t tokenDefinitionReferenceByteIntervalStart = U2BE(dataBuffer, dataOffset); dataOffset += 2;
		uint16_t tokenDefinitionReferenceByteIntervalCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

        ByteInterval tokenDefinitionReferenceByteInterval = { 
            .startsAt = tokenDefinitionReferenceByteIntervalStart,
            .byteCount = tokenDefinitionReferenceByteIntervalCount
        };

        ParticleMetaData metaDataAboutParticle = {
	        .addressOfRecipientByteInterval = addressOfRecipientByteInterval,
	        .amountByteInterval = amountByteInterval,
            .serializerValueByteInterval = serializerValueByteInterval,
	        .tokenDefinitionReferenceByteInterval = tokenDefinitionReferenceByteInterval 
        };

        if (isMetaDataForTransferrableTokensParticle(&metaDataAboutParticle)) {
            PRINTF("Got meta data about TransferrableTokensParticle\n");
        } else {
            PRINTF("Got meta data about NON-TransferrableTokensParticle\n");
        }

        ctx->metaDataAboutParticles[particleIndex] = metaDataAboutParticle;
    }

    // INITIATE SHA Hasher
    cx_sha256_init(&(ctx->hasher));

    // Start cached bytes buffer at 0 bytes, cached bytes are used
    // when data spans across two chunks.
    ctx->numberOfCachedBytes = 0;

    // INSTRUCTIONS ON HOW TO PARSE PARTICLES FROM ATOM RECEIVED => start parsing
    // This will be done in `ctx->atomByteCount / CHUNK_SIZE` number of chunks
    // by 'streaming' data in this chunks using multiple `io_exchange` calls.

    // parseAtom();
}