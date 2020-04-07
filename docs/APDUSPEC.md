# Cosmos App - Ledger Nano S
## General structure

The general structure of commands and responses is as follows:

#### Commands

| Field   | Type     | Content                | Note |
| :------ | :------- | :--------------------- | ---- |
| CLA     | byte (1) | Application Identifier | 0xAA |
| INS     | byte (1) | Instruction ID         |      |
| P1      | byte (1) | Parameter 1            |      |
| P2      | byte (1) | Parameter 2            |      |
| L       | byte (1) | Bytes in payload       |      |
| PAYLOAD | byte (L) | Payload                |      |

#### Response

| Field   | Type     | Content     | Note                     |
| ------- | -------- | ----------- | ------------------------ |
| ANSWER  | byte (?) | Answer      | depends on the command   |
| SW1-SW2 | byte (2) | Return code | see list of return codes |

#### Return codes

| Return code   | Description             |
| ------------- | ----------------------- |
| 0x6400        | Execution Error         |
| 0x6700        | Wrong length            | 
| 0x6982        | Empty buffer            |
| 0x6983        | Output buffer too small |
| 0x6986        | Command not allowed     |
| 0x6D00        | INS not supported       |
| 0x6E00        | CLA not supported       |
| 0x6F00        | Unknown                 |
| 0x9000        | Success                 |

Codes above should match [codes in implementation](https://github.com/radixdlt/radixdlt-ledger-app/blob/improve/change_cosmos_to_radix/deps/ledger-zxlib/include/apdu_codes.h)

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

### INS_GET_ADDR_SECP256K1

#### Command

| Field      | Type           | Content                        | Expected       |
| ---------- | -------------- | ------------------------------ | -------------- |
| CLA        | byte (1)       | Application Identifier         | 0xAA           |
| INS        | byte (1)       | Instruction ID                 | 0x02           |
| P1         | byte (1)       | Display address/path on device | 0x00 No        |
|            |                |                                | 0x01 Yes       |
| P2         | byte (1)       | Parameter 2                    | ignored        |
| Magic      | byte (1)       | Radix Universe Magic Byte      | ?              |
| Path[0]    | byte (4)       | Derivation Path Data           | 0x8000002c<sup id="x1">[1](#fx1)</sup>     |
| Path[1]    | byte (4)       | Derivation Path Data           | 0x80000218<sup id="x2">[2](#fx2)</sup>     |
| Path[2]    | byte (4)       | Derivation Path Data           | ?              |
| Path[3]    | byte (4)       | Derivation Path Data           | ?              |
| Path[4]    | byte (4)       | Derivation Path Data           | ?              |

<b id="fx1">1:</b> Hex of (hardened) derivation path: `44'` ([BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)).  
<b id="fx2">2:</b> Hex of Radix cointype,  (hardened) derivation path: `536'`.  

First three items in the derivation path will be automatically hardened

#### Response

Radix Address is `public key + magicByte + checksum`. Where the `magicByte` is the
most significant byte of the `Int32` called "magic", identifying the "Radix Universe". 

The address is 38 bytes: `1 (magic) + 33 (PKc) + 4 (Checksum)`. The checksum is the 4 most signigicant bytes of `SHA2-256bit` digest done _twice_, of `MagicByte | PKc`,
where `|` denotes concantenation and `PKc` denotes compressed public key.

| Field   | Type      | Content               | Note                     |
| ------- | --------- | --------------------- | ------------------------ |
| PK      | byte (33) | Compressed Public Key |                          |
| ADDR    | byte (38) | Radix Address         |                          |
| SW1-SW2 | byte (2)  | Return code           | see list of return codes |


### INS_SIGN_MESSAGE_SECP256K1

#### Command

| Field | Type      | Content                            | Expected  |
| ----- | --------- | ---------------------------------- | --------- |
| CLA   | byte (1)  | Application Identifier             | 0xAA      |
| INS   | byte (1)  | Instruction ID                     | 0x04      |
| P1    | byte (1)  | Payload desc                       | 0 = init  |
|       |           |                                    | 1 = add   |
|       |           |                                    | 2 = last  |
| P2    | byte (1)  | ----                               | not used  |
| L     | byte (2<sup id="a1">[1](#fa1)</sup>) | Length of "message" (2nd packet)   | (depends) |


<b id="fa1">1:</b> N.B. not all of those 16 bits can be used, in fact, [this document](https://buildmedia.readthedocs.org/media/pdf/ledger/latest/ledger.pdf) (section 18.1) suggests, that the max size of an application is 4096 bytes. Those we ought to limit max size of Message (DSON byte array) to max 2048 bytes, i.e. 11 bits.

The first packet/chunk includes only the derivation path

All other packets/chunks should contain message to sign 

*First Packet*

| Field      | Type     | Content                | Expected  |
| ---------- | -------- | ---------------------- | --------- |
| Path[0]    | byte (4) | Derivation Path Data   | 44        |
| Path[1]    | byte (4) | Derivation Path Data   | 536       |
| Path[2]    | byte (4) | Derivation Path Data   | ?         |
| Path[3]    | byte (4) | Derivation Path Data   | ?         |
| Path[4]    | byte (4) | Derivation Path Data   | ?         |

*Other Chunks/Packets*

| Field   | Type     | Content                                              | Expected |
| ------- | -------- | ---------------------------------------------------- | -------- |
| Message | bytes... | L<sup id="b1">[1](#fb1)</sup> number of bytes, a DSON<sup id="b2">[2](#fb2)</sup> serialized atom<sup id="b3">[3](#fb3)</sup> |          |

<b id="fb1">1:</b> Length of message, as an unsigned integer with 11 bits size, this value (field).  
is provided in initial `INS_SIGN_MESSAGE_SECP256K1` command.  
<b id="fb2">2:</b> DSON: is Radix DLT's own binary format, based on [CBOR - Consice Binary Object Representation](http://cbor.io/).  
<b id="fb3">3:</b> Atom: The name of the transaction container in the Radix DLT ecosystem.  

#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| SIG     | byte (64) | Signature   |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

--------------

### INS_SIGN_HASH_SECP256K1
(This command might be removed in the future in favour of `INS_SIGN_MESSAGE_SECP256K1`)

#### Command

| Field     | Type      | Content                    | Expected  |
| --------- | --------- | -------------------------- | --------- |
| CLA		| byte (1)  | Application Identifier     | 0xAA      |
| INS		| byte (1)  | Instruction ID             | 0x08      |
| P1 		| byte (1)  | Length of BIP32 Path       | 20<sup id="c1">[1](#fc1)</sup>    	 |
| P2 		| byte (1)  | Length of Hash to sign     | 32<sup id="c2">[2](#fc2)</sup>        |
| L  		| byte (1)  | Length of Payload          | P1 + P2   |
| Payload 	| byte (L)  | BIP32 path + Hash to sign  | (depends) |

<b id="fc1">1:</b> 5 derivation paths with 4 bytes each => 20 bytes.  
<b id="fc2">2:</b> SHA256 hashing algorighm used => 32 bytes long hash.  

#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| SIG     | byte (64) | Signature   |                          |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

