# Radix DLT App - Ledger Nano S
## General structure

The general structure of commands and responses is as follows:

### Commands

| Field   | Type     | Content                | Note |
| :------ | :------- | :--------------------- | ---- |
| CLA     | byte (1) | Application Identifier | 0xAA |
| INS     | byte (1) | Instruction ID         |      |
| P1      | byte (1) | Parameter 1            |      |
| P2      | byte (1) | Parameter 2            |      |
| L       | byte (1) | Bytes in payload       |      |
| PAYLOAD | byte (L) | Payload                |      |

### Response

| Field   | Type     | Content     | Note                     |
| ------- | -------- | ----------- | ------------------------ |
| ANSWER  | byte (?) | Answer      | depends on the command   |
| SW1-SW2 | byte (2) | Return code | see list of return codes |

### Return codes

#### Ledger's internal return codes
Please refer to [these codes found in `os.h`](https://github.com/LedgerHQ/nanos-secure-sdk/blob/master/include/os.h#L828-L846)

#### Radix Ledger app return codes

| Return code   | Description             |
| ------------- | ----------------------- |
| 0x6985 		| User rejected command   |
| 0x6B00		| Fatal error incorrect implementation |
| 0x6B01        | Invalid input       |
| 0x6D00        | Incorrect instruction identifier |
| 0x6E00        | Incorrect CLA  		  |
| 0x9000        | Success                 |

## Command definition

### INS_GET_VERSION

#### Command

| Field | Type     | Content                | Expected |
| ----- | -------- | ---------------------- | -------- |
| CLA   | byte (1) | Application Identifier | 0xAA     |
| INS   | byte (1) | Instruction ID         | 0x00     |
| P1    | byte (1) | Parameter 1            | ignored  |
| P2    | byte (1) | Parameter 2            | ignored  |
| L     | byte (1) | Bytes in payload       | 0        |

#### Response

| Field   | Type     | Content          | Note                            |
| ------- | -------- | ---------------- | ------------------------------- |
| CLA     | byte (1) | Test Mode        | 0xFF means test mode is enabled |
| MAJOR   | byte (1) | Version Major    |                                 |
| MINOR   | byte (1) | Version Minor    |                                 |
| PATCH   | byte (1) | Version Patch    |                                 |
| LOCKED  | byte (1) | Device is locked |                                 |
| SW1-SW2 | byte (2) | Return code      | see list of return codes        |

--------------

### INS_GEN_RADIX_ADDR

#### Command

| Field      | Type           | Content                        | Expected       |
| ---------- | -------------- | ------------------------------ | -------------- |
| CLA        | byte (1)       | Application Identifier         | 0xAA           |
| INS        | byte (1)       | Instruction ID                 | 0x01           |
| P1         | byte (1)       | Display address/path on device | 0x00 No confirmation |
|            |                |                                | 0x01 Require confirm of just address      |
|            |                |                                | 0x02 Require confirm of just BIP32 path      |
|            |                |                                | 0x03 Require confirm of both address and BIP32 Path  |
| P2         | byte (1)       | Radix Universe Magic Byte      | ?        |
| L          | byte (1)       | Length of Payload              | 12<sup id="ga1">[1](#ga1)</sup>             |
| |
| DEFINITION OF PAYLOAD |
| Path[2]    | byte (4)       | Derivation Path index 2 Data   | ?              |
| Path[3]    | byte (4)       | Derivation Path index 3 Data   | ?              |
| Path[4]    | byte (4)       | Derivation Path index 4 Data   | ?              |

<b id="ga1">1:</b> Three path components à 4 bytes => 12 bytes. The first two [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) components are hard coded to `44'/536'/` ([BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki))

**First item in the derivation path, data at index 2 (i.e. third component) will be automatically hardened**

#### Response

Radix Address is `public key + magicByte + checksum`. Where the `magicByte` is the
most significant byte of the `Int32` called "magic", identifying the "Radix Universe". 

The address is 38 bytes: `1 (magic) + 33 (PKc) + 4 (Checksum)`. The checksum is the 4 most signigicant bytes of `SHA2-256bit` digest done _twice_, of `MagicByte | PKc`,
where `|` denotes concantenation and `PKc` denotes compressed public key. 

The base58 encoding of the RadixAddress results in a 51-52 b58 characters long string, which is what is the respons of this instruction.

| Field   | Type      | Content               | Note                     |
| ------- | --------- | --------------------- | ------------------------ |
| ADDR    | byte (max 52) | Radix Address on b58 format  | Variable length 51 or 52 chars |
| SW1-SW2 | byte (2)  | Return code           | see list of return codes |


### INS_SIGN_ATOM_SECP256K1

Streaming of Atom data in multiple chunks/packets, first chunk will contain meta data about atom and instructions on how to [CBOR - Consice Binary Object Representation](http://cbor.io/) decode the particles in the atom.

#### Command

| Field | Type      | Content                            | Expected  |
| ----- | --------- | ---------------------------------- | --------- |
| CLA   | byte (1)  | Application Identifier             | 0xAA      |
| INS   | byte (1)  | Instruction ID                     | 0x02      |
| P1    | byte (1)  | Total no. of particles w spin UP   | ?         |
| P2    | byte (1)  | ----                               | not used  |
| L  		| byte (1)  | Length of Payload          | ?   |
| |
| DEFINITION OF PAYLOAD |
| Path[2]    | byte (4)       | Derivation Path index 2 Data   | ?              |
| Path[3]    | byte (4)       | Derivation Path index 3 Data   | ?              |
| Path[4]    | byte (4)       | Derivation Path index 4 Data   | ?              |
| AtomSize | byte (2<sup id="sa1">[1](#sa1)</sup>) | CBOR encoded Atom byte count | ? |
| MetaData UP Particles<sup id="sa2">[2](#sa2)</sup> | bytes | MetaData about how to CBOR decode each UP particle | `P1` * 16 bytes |

<b id="sa1">1:</b> Atom size as 2 bytes => 16 bits => 2^16 = 65536 bytes being MAX size of any Atom signed.

<b id="sa2">2:</b> Any Radix wallet calling this Ledger instruction/command <b>should</b> provide meta data about each particle with spin `UP`. The meta data consists of 4 byte intervals, being a touple (startsAtByte, byteCount) each consisting of 2 bytes => the byte interval is thus 4 bytes. 4*4 bytes => 16 bytes per particle meta data. These byte intervals points to the following fields within the spun `UP` particle (address, amount, serializer, tokenDefinitionReference) - in that order - for being able to parse TransferableTokensParticles (TokenTransfers). In the case of non-TransferrableTokensParticles, e.g. `MessageParticle`, `RRIParticle` etc, you must provide 4 ZERO bytes for (address, amount, tokenDefinition), but still provide the correct byte interval for `serializer` field. Thus BigEndian hex: `0x0000000000000000dead001700000000`, i.e. all fields are zero except for `serializer` having value `0xdead0018` for a MessageParticle, where `0xdead` = 57005<sub>10</sub> is the where (number of bytes from start of Atom) the field `serializer` for this MessageParticle starts, which is bound by 65536 (max size of atom). And where `0x0017` = 23<sub>10</sub> is number of characaters in the string "radix.particles.message" (the serializer value).

**First item in the derivation path, data at index 2 (i.e. third component) will be automatically hardened**

*Other Chunks/Packets*

| Field   | Type     | Content                                              | Expected |
| ------- | -------- | ---------------------------------------------------- | -------- |
| Atom chunk | bytes... | Chunk of max 255 bytes  |      ?    |


#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| SIG     | byte (64) | ECDSA Signature of hash  | Hash: SHA256-256 of CBOR encoded atom  |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

--------------

### INS_SIGN_HASH_SECP256K1
(This command might be removed in the future in favour of `INS_SIGN_ATOM_SECP256K1`)

#### Command

| Field     | Type      | Content                    | Expected  |
| --------- | --------- | -------------------------- | --------- |
| CLA		| byte (1)  | Application Identifier     | 0xAA      |
| INS		| byte (1)  | Instruction ID             | 0x04      |
| P1 		| byte (1)  | Length of BIP32 Path       | 20<sup id="sh1">[1](#sh1)</sup>    	 |
| P2 		| byte (1)  | Length of Hash to sign     | 32<sup id="sh2">[2](#sh2)</sup>        |
| L  		| byte (1)  | Length of Payload          | P1 + P2   |
| Payload 	| byte (L)  | BIP32 path + Hash to sign  | (depends) |

<b id="sh1">1:</b> 5 derivation paths with 4 bytes each => 20 bytes.  
<b id="sh2">2:</b> SHA256 hashing algorighm used => 32 bytes long hash.  

#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| SIG     | byte (64) | Signature   |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |


### INS_GET_PUB_KEY_SECP256K1
(This command might be removed in the future in favour of `INS_GET_ADDR_SECP256K1`)


#### Command

| Field     | Type          | Content                       | Expected      |
| --------- | ------------- | ----------------------------- | ------------- |
| CLA		| byte (1)   	| Application Identifier        | 0xAA      	|
| INS		| byte (1)   	| Instruction ID                | 0x08      	|
| P1 		| byte (1)   	| Confirm before generation     | 0x00 No confirmation of BIP32 path needed |
|    		|            	|                               | 0x01 Confirmation of BIP 32 path needed before generation of pub key  |
| P2 	    | byte (1)		| -----							| Not used |
| L         | byte (1)		| Number of bytes in Payload 	| 12<sup id="gpk1">[1](#gpk1)</sup>			|
| Payload 	| byte (L)		| BIP32 derivation path 		| (depends)	    |
	
<b id="gpk1">1:</b> 3 derivation paths with 4 bytes each => 12 bytes. We omit the first two paths, and let them be hardcoded to: "44'/536'" 


#### Response

| Field   | Type      | Content     			| Note                     |
| ------- | --------- | ----------------------- | ------------------------ |
| PK      | byte (33) | Compressed Public Key 	|                		   |
| SW1-SW2 | byte (2)  | Return code 			| see list of return codes |

