#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "radix.h"
#include "ux.h"
#include "sha256_hash.h"
#include "cbor.h"

// Get a pointer to signHash's state variables. This is purely for
// convenience, so that we can refer to these variables concisely from any
// signHash-related function.
static signAtomContext_t *ctx = &global.signAtomContext;

#define LEDGER_MEMORY_MAX 1660 // dependent on size of code?

typedef enum { Integer, ByteString, TextString } ParsedCborValueKind;

typedef struct {
    ParsedCborValueKind kind;
    union {
        struct { int64_t integer; }; /* CborIntegerType */
        struct { uint8_t *byte_string, uint8_t byte_string_length; }; /* CborByteStringType */
        struct { char *text_string, uint8_t text_string_length; }; /* CborTextStringType */
    };
} ParsedCborValue;

void setIntegerValue(ParsedCborValue *parsedCborValue, int64_t value) {
    parsedCborValue->kind = Integer;
    parsedCborValue->integer = value;
}

int64_t getInteger(ParsedCborValue *parsedCborValue) {
    assert(parsedCborValue->kind == Integer);
    return parsedCborValue->integer;
}


void setByteStringValue(
    ParsedCborValue *parsedCborValue, 
    uint8_t *byte_string, uint8_t byte_string_length
) {
    parsedCborValue->kind = ByteString;
    // os_memcpy(parsedCborValue->byte_string, byte_string, byte_string_length);
    parsedCborValue->byte_string = byte_string;
    parsedCborValue->byte_string_length = byte_string_length;
}

const uint8_t* getByteString(
    ParsedCborValue *parsedCborValue, 
    size_t *output_length_of_string_to_read
) {
    assert(parsedCborValue->kind == ByteString);
    *output_length_of_string_to_read = parsedCborValue->byte_string_length;
    return parsedCborValue->byte_string;
}

void setTextStringValue(
    ParsedCborValue *parsedCborValue, 
    char *text_string, uint8_t text_string_length
) {
    parsedCborValue->kind = TextString;
    // os_memcpy(parsedCborValue->byte_string, byte_string, byte_string_length);
    parsedCborValue->text_string = text_string;
    parsedCborValue->text_string_length = text_string_length;
}

const char* getTextString(
    ParsedCborValue *parsedCborValue, 
    size_t *output_length_of_string_to_read
) {
    assert(parsedCborValue->kind == TextString);
    *output_length_of_string_to_read = parsedCborValue->text_string_length;
    return parsedCborValue->text_string;
}


void printParsedCborValue(ParsedCborValue *parsedCborValue) {
    switch parsedCborValue->kind {
        case Integer: {
            PRITNF("Successfully parsed integer from cbor: %d\n", getInteger(parsedCborValue));
            break;
        }

        case ByteString: {
            size_t byteStringLength;
            const uint8_t *byteString = getByteString(parsedCborValue, &byteStringLength);
            PRINTF("Successfully parsed byteString from cbor: %.*H\n", byteStringLength, byteString);
            break;
        }

        case TextString: {
            size_t textStringLength;
            const char *textString = getTextString(parsedCborValue, &textStringLength);
            PRINTF("Successfully parsed textString from cbor: %.*s\n", textStringLength, textString);
            break;
        }

        default: {
            PRINTF("Unsupported ParsedCborValue, kind: %d\n", parsedCborValue->kind);
            break;
        }
    }
}


/// ###### START CBOR STUFF #####

static CborError dumprecursive(
    CborValue *it,
    int nestingLevel,
    // Callback / "Closure" when CborParser found a value
    void (*successfullyParsedCborValueCallBack)(ParsedCborValue*)
) {
    while (!cbor_value_at_end(it)) {
        CborError err;
        CborType type = cbor_value_get_type(it);

        // indent(nestingLevel);
        switch (type) {
        case CborArrayType:
        case CborMapType: {
            // recursive type
            CborValue recursed;
            assert(cbor_value_is_container(it));
            // puts(type == CborArrayType ? "Array[" : "Map[");
            err = cbor_value_enter_container(it, &recursed);
            if (err)
                return err;       // parse error
            err = dumprecursive(&recursed, nestingLevel + 1, successfullyParsedCborValueCallBack);
            if (err)
                return err;       // parse error
            err = cbor_value_leave_container(it, &recursed);
            if (err)
                return err;       // parse error
            // indent(nestingLevel);
            // puts("]");
            continue;
        }

        case CborIntegerType: {
            int64_t val;
            cbor_value_get_int64(it, &val);     // can't fail

            ParsedCborValue cborValue;
            setIntegerValue(&cborValue, val)
            successfullyParsedCborValueCallBack(&cborValue);

            // printf("%lld\n", (long long)val);
            break;
        }

        case CborByteStringType: {
            uint8_t *buf;
            size_t n;
            err = cbor_value_dup_byte_string(it, &buf, &n, it);
            if (err)
                return err;     // parse error

            ParsedCborValue cborValue;
            setByteString(&cborValue, buf, n)
            successfullyParsedCborValueCallBack(&cborValue);
            
            // dumpbytes(buf, n);
            // puts("");
            // free(buf);
            continue;
        }

        case CborTextStringType: {
            char *buf;
            size_t n;
            err = cbor_value_dup_text_string(it, &buf, &n, it);
            if (err)
                return err;     // parse error

            ParsedCborValue cborValue;
            setTextString(&cborValue, buf, n)
            successfullyParsedCborValueCallBack(&cborValue);
            // puts(buf);
            // free(buf);
            continue;
        }

        case CborTagType: {
            CborTag tag;
            cbor_value_get_tag(it, &tag);       // can't fail
            PRINTF("Found cbor `tag`: (%lld)\n", (long long)tag);
            break;
        }

        case CborSimpleType: {
            uint8_t type;
            cbor_value_get_simple_type(it, &type);  // can't fail
            PRINTF("Found cbor `simple`: (%u)\n", type);
            break;
        }

        case CborNullType:
            PRITNF("null\n");
            break;

        case CborUndefinedType:
            PRITNF("undefined\n");
            break;

        case CborBooleanType: {
            bool val;
            cbor_value_get_boolean(it, &val);       // can't fail
            PRINTF(val ? "Found cbor boolean - value: `true`\n" : "Found cbor boolean - value: `false`\n");
            break;
        }

        case CborDoubleType: {
            double val;
            if (false) {
                float f;
        case CborFloatType:
                cbor_value_get_float(it, &f);
                val = f;
            } else {
                cbor_value_get_double(it, &val);
            }
            PRINTF("Found cbor float: %g\n", val);
            break;
        }
        case CborHalfFloatType: {
            uint16_t val;
            cbor_value_get_half_float(it, &val);
            PRINTF("Found cbor half float:  __f16(%04x)\n", val);
            break;
        }

        case CborInvalidType:
            assert(false);      // can't happen
            break;
        }

        err = cbor_value_advance_fixed(it);
        if (err)
            return err;
    }
    return CborNoError;
}

/// ###### END CBOR STUFF ######

static void emptyChunkBuffer() {
    os_memset(ctx->chunkBuffer, 0, MAX_CHUNK_SIZE);
}

static void readNextChunkFromHostMachine(
    size_t numberOfBytesToRead
) {
    G_io_apdu_buffer[0] = 0x90;
    G_io_apdu_buffer[1] = 0x00;
	unsigned rx = io_exchange(CHANNEL_APDU, 2);
	PRINTF("readNextChunkFromHostMachine: io_exchanged %d bytes\n", rx);
    // N.B. we do not provide any meta data at all for chunked data,
    // not in the databuffer any way, we might use P1, P2 here...
	uint32_t dataOffset = OFFSET_CDATA + 0;

    // "Clean" buffer from any old data before writing to it, for good measure
    emptyChunkBuffer();
    os_memcpy(ctx->chunkBuffer, G_io_apdu_buffer + dataOffset, numberOfBytesToRead);
}

typedef enum { 
    nil = 0,
    TransferrableTokensParticle = 1,
    NonTransferrableTokensParticle = 2
} RadixParticleParsingNowKind;

typedef enum {
    notYetKnown = 0;
    MessageParticle = 1, UniqueParticle, TokenDefFixedParticle, TokenDefMutParticle, RRIParticle, UnallocatedTokensParticle
} RadixParticleNonTransferrable;

typedef struct {
    RadixParticleParsingNowKind kind;
    union {
        struct { RRI rri; Amount amount; Address recipient; }; 
        struct { RadixParticleNonTransferrable particleTypeNonTransf; };        
    };
} RadixParticleBeingParsed;

int setParsingParticleTransferrable(
    RadixParticleBeingParsed *radixParticleBeingParsed,
    RRI rri, Amount amount, Address recipient
) {
    radixParticleBeingParsed->kind = TransferrableTokensParticle
    
    if (rri && !radixParticleBeingParsed->rri)
        radixParticleBeingParsed->rri = rri;
    
    if (amount && !radixParticleBeingParsed->amount)
        radixParticleBeingParsed->amount = amount;

    if (recipient && !radixParticleBeingParsed->recipient)
        radixParticleBeingParsed->recipient = recipient;
}

int setParsingParticleNonTransferrable(
    RadixParticleBeingParsed *radixParticleBeingParsed,
    RadixParticleNonTransferrable particleTypeNonTransf
) {
    radixParticleBeingParsed->kind = NonTransferrableTokensParticle;
    radixParticleBeingParsed->particleTypeNonTransf = particleTypeNonTransf;
}

typedef enum { 
    nil = 0,
    Serializer = 1,
    Address = 2,
    RRI = 3, 
    Amount = 4
} RadixEntityKind;

typedef struct {
    RadixEntityKind nextRadixEntityKind;
    RadixParticleBeingParsed radixParticleBeingParsed;
} DecodeCborContext;
DecodeCborContext decodeCborContext;

static void didParseCborValue(ParsedCborValue *parsedCborValue) {
    printParsedCborValue(parsedCborValue);
    switch parsedCborValue->kind {
        case TextString: {
            size_t textStringLength;
            const char *textStringPointer = getTextString(parsedCborValue, &textStringLength);
            char textString[textStringLength+1];
            int writtenLength = SPRINTF(textString, "%s", textStringPointer);
            if (writtenLength != textStringLength+1) {
                FAIL("Expected written length to be: %d, but was: %d\n", textStringLength+1, writtenLength);
            }
            PRITNF("textString: %s\n", textString);

            if (decodeCborContext->nextRadixEntityKind) {
                switch (nextRadixEntityKind) {
                    case Serializer: {
                        if (textString == "radix.particles.transferrable_tokens") {
                            //
                            setParsingParticleTransferrable(decodeCborContext->radixParticleBeingParsed, NULL, NULL, NULL);
                        } else {
                            if (textString == "radix.particles.message") {
                                setParsingParticleNonTransferrable(
                                    decodeCborContext->radixParticleBeingParsed,
                                    MessageParticle
                                );
                            }
                            else if (textString == "radix.particles.rri") {
                                setParsingParticleNonTransferrable(
                                    decodeCborContext->radixParticleBeingParsed,
                                    RRIParticle
                                );
                            }
                            else if (textString == "radix.particles.fixed_supply_token_definition") {
                                setParsingParticleNonTransferrable(
                                    decodeCborContext->radixParticleBeingParsed,
                                    TokenDefFixedParticle
                                );
                            }
                            else if (textString == "radix.particles.mutable_supply_token_definition") {
                                setParsingParticleNonTransferrable(
                                    decodeCborContext->radixParticleBeingParsed,
                                    TokenDefMutParticle
                                );
                            }
                            else if (textString == "radix.particles.unallocated_tokens") {
                                setParsingParticleNonTransferrable(
                                    decodeCborContext->radixParticleBeingParsed,
                                    UnallocatedTokensParticle
                                );
                            }
                            else if (textString == "radix.particles.unique") {
                                setParsingParticleNonTransferrable(
                                    decodeCborContext->radixParticleBeingParsed,
                                    UniqueParticle
                                );
                            }
                        }
                        break;
                    }

                    default: {
                        break;
                    }
                }
            } else {
                if (textString == "!serializer") {
                    decodeCborContext->nextRadixEntityKind = Serializer;
                }  
                else if (textString == "address") {
                    decodeCborContext->nextRadixEntityKind = Address;
                }
                else if (textString == "amount") {
                    decodeCborContext->nextRadixEntityKind = Amount;
                }
                else if (textString == "tokenDefinitionReference") {
                    decodeCborContext->nextRadixEntityKind = RRI;
                }
                else {
                    PRITNF("unhandled textString: %s\n", textString);
                    decodeCborContext->nextValueIsSerializer = nil;
                }
            }

            break;
        }
    }
}

// Returns a boolean value indicating whether or not all `ctx->atomByteCount` bytes
// have been parsed, i.e. the whole atom has been parsed.
static bool parseParticlesAndUpdateHash() {
    uint16_t bytesLeftToRead = ctx->atomByteCount - ctx->atomByteCountParsed;
	uint16_t numberOfBytesToRead = min(MAX_CHUNK_SIZE, bytesLeftToRead);
	bool shouldFinalizeHash = numberOfBytesToRead < MAX_CHUNK_SIZE;

    readNextChunkFromHostMachine((size_t)numberOfBytesToRead);

    // UPDATE HASH
    sha256_hash(
        &(ctx->hasher),
        ctx->chunkBuffer,
        (size_t)numberOfBytesToRead,
        shouldFinalizeHash,
        (shouldFinalizeHash ? ctx->hash : NULL)
    );

    // Since we might have cahced data from last slice, best use a new byte array 
    // concatenating `cached + newlyReceived` bytes.
    // TODO can save 255 bytes by optimising this, but requires cached bytes logic in more places.
    uint8_t atomSlice[MAX_CHUNK_SIZE + MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS];
    size_t atomSliceByteCount = 0;

    // Check if we have any cached bytes from last chunk
    if (ctx->numberOfCachedBytes > 0) {

        // bytes from cached -> atomSlice
        os_memcpy(atomSlice, ctx->cachedSmallBuffer, ctx->numberOfCachedBytes);
        atomSliceByteCount = ctx->numberOfCachedBytes;
        
        // "Clean" cached buffer, since data has been copied over
        os_memset(ctx->cachedSmallBuffer, 0, MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS);
        // No cached bytes left
        ctx->numberOfCachedBytes = 0;
    }
    // Copy newly received chunk bytes over to atomSlice.
    os_memcpy(
        atomSlice + atomSliceByteCount, // `atomSliceByteCount` is 0 if no cached data was copied over 
        ctx->chunkBuffer, 
        numberOfBytesToRead
    );
    atomSliceByteCount += numberOfBytesToRead;
    // From this point we will be using `atomSlice` instead. Until next chunk.
    emptyChunkBuffer();


    size_t numberOfParsedBytesInAtomSlice = 0;
    CborParser cborParser;
    CborValue cborValue;
    
    CborError cborErr = cbor_parser_init(
        atomSlice, 
        atomSliceByteCount, 
        0, // flags
        &cborParser,
        &cborValue
    );

    if(cborError) {
        PRINTF("Got CBOR error, hmm is this maybe expected? What to do?, error: %s\n", cbor_error_string(cborError));
        THROW(0x9876);
    }

    for (; ctx->numberOfParticlesParsed < ctx->numberOfParticlesWithSpinUp; ++(ctx->numberOfParticlesParsed)) {
        OffsetInAtom particle = ctx->offsetsOfParticlesWithSpinUp[ctx->numberOfParticlesParsed];

        while (!cborError) {
            cbor = dumprecursive(&cborValue, 0, didParseCborValue);
        }

        PRINTF("cborValue.remaining: %u\n", cborValue->remaining);
        PRINTF("cborValue.extra: %u\n", cborValue->extra);
        if (cborParser->end) {
            PRINTF("cborParser->end is NOT null\n");
        }
    }
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
    ctx->atomByteCount = U2LE(dataBuffer, dataOffset); dataOffset += 2;
    ctx->atomByteCountParsed = 0;

    // READ offsets to particles from first chunk, available directly
    ctx->numberOfParticlesParsed = 0;
    for (uint8_t particleIndex = 0; particleIndex < ctx->numberOfParticlesWithSpinUp; ++particleIndex) {
        uint16_t particleStartsAt = U2LE(dataBuffer, dataOffset); dataOffset += 2;
		uint16_t particleByteCount = U2LE(dataBuffer, dataOffset); dataOffset += 2;
        OffsetInAtom particleOffsetInAtom = { 
            .startsAt = particleStartsAt,
            .byteCount =particleByteCount
        };
        ctx->offsetsOfParticlesWithSpinUp[particleIndex] = particleOffsetInAtom;
    }

    // INITIATE SHA Hasher
    cx_sha256_init(&(ctx->hasher));

    // Start cached bytes buffer at 0 bytes, cached bytes are used
    // when data spans across two chunks.
    ctx->numberOfCachedBytes = 0;

    // INSTRUCTIONS ON HOW TO PARSE PARTICLES FROM ATOM RECEIVED => start parsing
    // This will be done in `ctx->atomByteCount / CHUNK_SIZE` number of chunks
    // by 'streaming' data in this chunks using multiple `io_exchange` calls.

    parseAtom();
}