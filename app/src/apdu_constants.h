#ifndef BTCHIP_APDU_CONSTANTS_H

#define BTCHIP_APDU_CONSTANTS_H

// APDU Command structure
// These are the offsets of various parts of a request APDU packet. INS
// identifies the requested command (see above), and P1 and P2 are parameters
// to the command.
#define CLA          0xAA

#define OFFSET_CLA   0x00
#define OFFSET_INS   0x01
#define OFFSET_P1    0x02
#define OFFSET_P2    0x03
#define OFFSET_LC    0x04
#define OFFSET_CDATA 0x05

// APDU Software Interrupt (Error / Exception code)
// copied from Bitcoin Ledger App:
// https://github.com/LedgerHQ/ledger-app-btc/blob/c41e78c4fc71daa85527ed6e0cd542f224279801/include/btchip_apdu_constants.h

#define SW_PIN_REMAINING_ATTEMPTS						0x63C0
#define SW_INCORRECT_LENGTH								0x6700
#define SW_COMMAND_INCOMPATIBLE_FILE_STRUCTURE			0x6981
#define SW_SECURITY_STATUS_NOT_SATISFIED				0x6982
#define SW_CONDITIONS_OF_USE_NOT_SATISFIED				0x6985
#define SW_INCORRECT_DATA								0x6A80
#define SW_NOT_ENOUGH_MEMORY_SPACE						0x6A84
#define SW_REFERENCED_DATA_NOT_FOUND					0x6A88
#define SW_FILE_ALREADY_EXISTS							0x6A89
#define SW_INCORRECT_P1_P2								0x6B00
#define SW_INS_NOT_SUPPORTED							0x6D00
#define SW_CLA_NOT_SUPPORTED							0x6E00
#define SW_TECHNICAL_PROBLEM							0x6F00

// Special one
#define SW_OK											0x9000

#define SW_MEMORY_PROBLEM								0x9240
#define SW_NO_EF_SELECTED								0x9400
#define SW_INVALID_OFFSET								0x9402
#define SW_FILE_NOT_FOUND								0x9404
#define SW_INCONSISTENT_FILE							0x9408
#define SW_ALGORITHM_NOT_SUPPORTED						0x9484
#define SW_INVALID_KCV									0x9485
#define SW_CODE_NOT_INITIALIZED							0x9802
#define SW_ACCESS_CONDITION_NOT_FULFILLED				0x9804
#define SW_CONTRADICTION_SECRET_CODE_STATUS				0x9808
#define SW_CONTRADICTION_INVALIDATION					0x9810
#define SW_CODE_BLOCKED									0x9840
#define SW_MAX_VALUE_REACHED							0x9850
#define SW_GP_AUTH_FAILED								0x6300
#define SW_LICENSING									0x6F42
#define SW_HALTED										0x6FAA

// UX
#define SW_USER_REJECTED                                0x6900

// Radix ones
#define RADIX_SW_HASH_NOT_32_BYTES                                      0x6F01
#define RADIX_SW_ALLOCATED_MEMORY_FOR_OUTPUT_SIGNATURE_NOT_64_BYTES     0x6F02
#define RADIX_SW_BIP32_CHANGE_NOT_ZERO_OR_ONE                           0x6F03
#define RADIX_SW_INS_SIGN_HASH_DATA_INPUT_WRONG_SIZE                    0x6F04
#define RADIX_SW_FAILED_TO_DISPATCH_INS				                    0x6F05

// Constants
#define ECDSA_SIGNATURE_OUTPUT_BYTE_COUNT                   64
#define ECDSA_SIGNATURE_INPUT_HASH_EXPECTED_BYTE_COUNT      32
#define BIP32_PATH_COMPONENT_BYTE_COUNT                     4       
#define BIP32_PATH_COMPONENTS_EXPECTED_COUNT_FROM_INPUT     3       
#define BIP32_PATH_FULL_NUMBER_OF_COMPONENTS     			5       
#define BIP32_PATH_FULL_BYTE_COUNT     						(BIP32_PATH_COMPONENT_BYTE_COUNT * BIP32_PATH_FULL_NUMBER_OF_COMPONENTS)      
#define BIP32_PATH_COMPONENTS_INPUT_EXPECTED_BYTE_COUNT     (BIP32_PATH_COMPONENT_BYTE_COUNT * BIP32_PATH_COMPONENTS_EXPECTED_COUNT_FROM_INPUT)
#define SIGN_HASH_INS_PAYLOAD_EXPECTED_BYTE_COUNT           (BIP32_PATH_COMPONENTS_INPUT_EXPECTED_BYTE_COUNT + ECDSA_SIGNATURE_INPUT_HASH_EXPECTED_BYTE_COUNT)


#endif