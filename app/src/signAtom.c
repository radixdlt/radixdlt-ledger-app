#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "radix.h"
#include "ux.h"
#include "sha256_hash.h"
#include "cbor.h"
// #include "RadixAddress.h"
// #include "RadixResourceIdentifier.h"
// #include "Transfer.h"

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

// static ParticleField nextField(
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


static ByteInterval getNextByteInterval() {
    ParticleMetaData particleMetaData = ctx->metaDataAboutParticles[ctx->numberOfParticlesParsed];
    switch (ctx->nextFieldInParticleToParse) {
        case AddressField: 
            return particleMetaData.addressOfRecipientByteInterval;
        case AmountField: 
            return particleMetaData.amountByteInterval;
        case SerializerField: 
            return particleMetaData.serializerValueByteInterval;
        case TokenDefinitionReferenceField: 
            return particleMetaData.tokenDefinitionReferenceByteInterval;
    }
}

static void emptyAtomSlice() {
    os_memset(ctx->atomSlice, 0, MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS + MAX_CHUNK_SIZE);
}

static bool isFieldSet(ParticleField field) {
    size_t byteCount;
    size_t offsetInTransferStruct;
    switch (field) {
        case AddressField: 
            byteCount = sizeof(RadixAddress);
            offsetInTransferStruct = 0;
            break;
        case AmountField:
            byteCount = sizeof(TokenAmount);
            offsetInTransferStruct = sizeof(RadixAddress);
            break;
        case TokenDefinitionReferenceField:
            byteCount = sizeof(RadixResourceIdentifier);
            offsetInTransferStruct = sizeof(RadixAddress) + sizeof(TokenAmount);
            break;
        default: FATAL_ERROR("Unknown field: %d", field);
    }

    for (size_t i = 0; i < byteCount; ++i) {
        unsigned char byte = *(
            ctx->transfers[ctx->numberOfParticlesParsed].address.bytes + offsetInTransferStruct + i
        );
        if (byte > 0x00) {
            return true;
        }
    }
    return false;
}

static void parseAddress(
    const size_t fieldByteCount,
    CborValue *cborValue
)
{
    // +1 byte for CBOR byte string Radix additional encoding prefix
    assert(fieldByteCount == (1 + sizeof(RadixAddress)));

    size_t numberOfBytesReadByCBORParser;
    uint8_t byteString[fieldByteCount];
    CborError cborError = cbor_value_copy_byte_string(
        cborValue,
        byteString,
        &numberOfBytesReadByCBORParser,
        NULL);


    if (cborError)
    {
        FATAL_ERROR("Error parsing 'address' field in atomSlice, CBOR eror: '%s'\n", cbor_error_string(cborError)); // will terminate app
    }

    // Sanity check
    assert(numberOfBytesReadByCBORParser == fieldByteCount);
    assert(byteString[0] == ByteStringCBORPrefixByte_address);
    assert(!isFieldSet(AddressField));
    assert(!isFieldSet(AmountField));

    os_memcpy(
        ctx->transfers[ctx->numberOfParticlesParsed].address.bytes,
        // Drop first byte, since it only specifies the `address` type.
        byteString + 1,
        sizeof(RadixAddress)
    );

    // Sanity check
    assert(isFieldSet(AddressField));
}

static void parseAmount(
    const size_t fieldByteCount,
    CborValue *cborValue
)
{
    // +1 byte for CBOR byte string Radix additional encoding prefix
    assert(fieldByteCount == (1 + sizeof(TokenAmount)));

    size_t numberOfBytesReadByCBORParser;
    uint8_t byteString[fieldByteCount];
    CborError cborError = cbor_value_copy_byte_string(
        cborValue,
        byteString,
        &numberOfBytesReadByCBORParser,
        NULL);


    if (cborError)
    {
        FATAL_ERROR("Error parsing 'amount' field in atomSlice, CBOR eror: '%s'\n", cbor_error_string(cborError));
    }

    // Sanity check
    assert(numberOfBytesReadByCBORParser == fieldByteCount);
    assert(byteString[0] == ByteStringCBORPrefixByte_uint256);
    assert(isFieldSet(AddressField));
    assert(!isFieldSet(AmountField));

    os_memcpy(
        ctx->transfers[ctx->numberOfParticlesParsed].amount.bytes,
        // Drop first byte, since it only specifies the `amount` type.
        byteString + 1,
        sizeof(TokenAmount));

    // Sanity check
    assert(isFieldSet(AmountField));
}

static void parseSerializer(
    const size_t fieldByteCount,
    CborValue *cborValue
) 
{
    size_t numberOfBytesReadByCBORParser;
    char textString[fieldByteCount];
    CborError cborError = cbor_value_copy_text_string(
        cborValue,
        textString,
        &numberOfBytesReadByCBORParser,
        NULL);

    assert(numberOfBytesReadByCBORParser == fieldByteCount);

    if (cborError)
    {
        FATAL_ERROR("Error parsing 'serializer' field in atomSlice, CBOR eror: '%s'\n", cbor_error_string(cborError)); // will terminate app
    }

    RadixParticleTypes particleType = particleTypeFromUTF8String(textString, fieldByteCount);

    // if `Address` or `Amount` is parsed, means that we expect this particle to be a TransferrableTokensParticle (since "serializer" comes before "tokenDefinitionReference" alphabetically and thus also in CBOR it is not set yet)
    if (isFieldSet(AddressField) || isFieldSet(AmountField))
    {
        if (particleType != TransferrableTokensParticleType)
        {
            FATAL_ERROR("Incorrect particle type, expected `TransferrableTokensParticle`, but got other.");
        }
        ctx->identifiedParticleTypesInAtom[ctx->numberOfParticlesParsed] = particleType;
    } else if (particleType == TransferrableTokensParticleType && !(isFieldSet(AddressField) && isFieldSet(AmountField))) {
        FATAL_ERROR("Got `TransferrableTokensParticle`, but amount and address fields are NULL.");
    }

    if (particleType != TransferrableTokensParticleType) {
        ctx->numberOfParticlesParsed++;
    }
}

static void parseTokenDefinitionReference(
    const size_t fieldByteCount,
    CborValue *cborValue
)
{
    // +1 byte for CBOR byte string Radix additional encoding prefix
    assert(fieldByteCount == (1 + sizeof(RadixResourceIdentifier)));

    size_t numberOfBytesReadByCBORParser;
    uint8_t byteString[fieldByteCount];
    CborError cborError = cbor_value_copy_byte_string(
        cborValue,
        byteString,
        &numberOfBytesReadByCBORParser,
        NULL);

    if (cborError)
    {
        FATAL_ERROR("Error parsing 'tokenDefinitionReference' field in atomSlice, CBOR eror: '%s'\n", cbor_error_string(cborError));
    }

    // Sanity check
    assert(numberOfBytesReadByCBORParser == fieldByteCount);
    assert(byteString[0] == ByteStringCBORPrefixByte_rri);
    assert(isFieldSet(AddressField));
    assert(isFieldSet(AmountField));
    assert(!isFieldSet(TokenDefinitionReferenceField));

    os_memcpy(
        ctx->transfers[ctx->numberOfParticlesParsed].tokenDefinitionReference.bytes,
        // Drop first byte, since it only specifies the `RRI` type.
        byteString + 1,
        sizeof(RadixResourceIdentifier));

    assert(isFieldSet(TokenDefinitionReferenceField));
}

static void parseParticleFieldFromAtomSlice(
    const size_t fieldPositionInAtomSlice,
    const size_t fieldByteCount
) {
    CborParser cborParser;
    CborValue cborValue;
    CborError cborError = cbor_parser_init(
        ctx->atomSlice + fieldPositionInAtomSlice, 
        fieldByteCount,
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

    assert(readLength == fieldByteCount);

    switch (ctx->nextFieldInParticleToParse) {
        case AddressField:
            assert(type == CborByteStringType);
            parseAddress(fieldByteCount, &cborValue);
            break;
        case AmountField: 
            assert(type == CborByteStringType);
            parseAmount(fieldByteCount, &cborValue);
            break;
        case SerializerField: 
            assert(type == CborTextStringType);
            parseSerializer(fieldByteCount, &cborValue);
            break;
        case TokenDefinitionReferenceField: 
            assert(type == CborByteStringType);
            parseTokenDefinitionReference(fieldByteCount, &cborValue);
            break;
    }
    
    // [address, amount, serializer, tokenDefintionReference]
    int numberOfFieldsOfInterest = 4; 
    ctx->nextFieldInParticleToParse = (ctx->nextFieldInParticleToParse + 1) % numberOfFieldsOfInterest; 

    // Check if we finished parsing a whole transferrable tokens particle
    if (ctx->nextFieldInParticleToParse == AddressField) {
        ctx->numberOfParticlesParsed++;
    }
}

static void cacheBytesIfNeeded(
    const size_t atomSliceByteCount,
    const size_t fieldPositionInAtomSlice,
    const size_t fieldByteCount
) {
    size_t numberOfBytesToCache = atomSliceByteCount - fieldByteCount;

    uint8_t tmp[numberOfBytesToCache]; // uint8_t tmp[MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS];

    os_memcpy(
        tmp,
        ctx->atomSlice + fieldPositionInAtomSlice,
        numberOfBytesToCache);

    emptyAtomSlice();

    os_memcpy(
        ctx->atomSlice,
        tmp,
        numberOfBytesToCache);

    ctx->numberOfCachedBytes = numberOfBytesToCache;
    ctx->atomByteCountParsed -= numberOfBytesToCache;
}

// Returns a boolean value indicating whether or all particles have been parsed
static bool parseParticlesAndUpdateHash() {
    uint16_t bytesLeftToRead = ctx->atomByteCount - ctx->atomByteCountParsed;
	uint16_t chunkSize = MIN(MAX_CHUNK_SIZE, bytesLeftToRead);

    readNextChunkFromHostMachineAndUpdateHash((size_t)chunkSize);
    size_t numberOfCachedBytes = ctx->numberOfCachedBytes;
    ctx->numberOfCachedBytes = 0;
    size_t atomSliceByteCount = chunkSize + numberOfCachedBytes;
    size_t atomByteCountParsedBeforeThisChunk = ctx->atomByteCountParsed;
    ctx->atomByteCountParsed = atomByteCountParsedBeforeThisChunk + chunkSize;

    bool doneParsingThisAtomSlice = false;

    // parse particles and their values from current atom slice
    while (!doneParsingThisAtomSlice) { 
        ByteInterval fieldByteInterval = getNextByteInterval();
        
        size_t fieldByteCount = fieldByteInterval.byteCount;
        size_t fieldPositionInAtom = fieldByteInterval.startsAt;

        size_t fieldPositionInAtomSlice = fieldPositionInAtom - atomByteCountParsedBeforeThisChunk + numberOfCachedBytes;

        doneParsingThisAtomSlice = fieldPositionInAtomSlice + fieldByteCount >= atomSliceByteCount;
        if (doneParsingThisAtomSlice) {
            // Check if needs to cache
            bool fieldSpillOverToNextChunk = fieldPositionInAtomSlice + fieldByteCount > atomSliceByteCount;
            if (fieldSpillOverToNextChunk) {
                cacheBytesIfNeeded(atomSliceByteCount, fieldPositionInAtomSlice, fieldByteCount);
                return false;
            }
        } else {
            // Can parse a field from current atom slice
            parseParticleFieldFromAtomSlice(fieldPositionInAtomSlice, fieldByteCount);
        }
    }
    
    emptyAtomSlice();

    return ctx->numberOfParticlesParsed >= ctx->numberOfParticlesWithSpinUp;
}

static void parseAtom() {

    while(!parseParticlesAndUpdateHash()) {
        PRINTF("Finished parsing %u/%u particles", ctx->numberOfParticlesParsed, ctx->numberOfParticlesWithSpinUp);
        PRINTF("Finished parsing %u/%u bytes of the Atom", ctx->atomByteCountParsed, ctx->atomByteCount);
    }
    assert(ctx->atomByteCountParsed == ctx->atomByteCount)
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

    os_memset(ctx->transfers, 0, MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP * sizeof(Transfer));

    // INSTRUCTIONS ON HOW TO PARSE PARTICLES FROM ATOM RECEIVED => start parsing
    // This will be done in `ctx->atomByteCount / CHUNK_SIZE` number of chunks
    // by 'streaming' data in this chunks using multiple `io_exchange` calls.

    parseAtom();
}