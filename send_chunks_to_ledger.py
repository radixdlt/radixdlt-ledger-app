#!/usr/bin/env python3

from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
import argparse
import struct
import math
from hashlib import sha256


def expected_printed_output():
	return """
Transfer at index: 0
Address b58: JEyoKNEYawJkNTiinQh1hR9c3F57ANixyBRi9fsSEfGedumiffR
Amount (dec): 999 E-18
Token symbol: ZELDA


Transfer at index: 1
Address b58: JFeqmatdMyjxNce38w3pEfDeJ9CV6NCkygDt3kXtivHLsP3p846
Amount (dec): 1 E-18
Token symbol: ZELDA


Transfer at index: 2
Address b58: JEyoKNEYawJkNTiinQh1hR9c3F57ANixyBRi9fsSEfGedumiffR
Amount (dec): 997 E-18
Token symbol: ZELDA


Transfer at index: 3
Address b58: JG3Ntbhj144hpz2ZooKsQG3Hq7UkCMwmFMwXfaYQgKFzNXAQvo5
Amount (dec): 2 E-18
Token symbol: ZELDA


Transfer at index: 4
Address b58: JEyoKNEYawJkNTiinQh1hR9c3F57ANixyBRi9fsSEfGedumiffR
Amount (dec): 994 E-18
Token symbol: ZELDA


Transfer at index: 5
Address b58: JFtJPDGvw4NDQyqCk7P5pWudNMeT8TFGCSvY9pTEqiyVhUGM9R9
Amount (dec): 3 E-18
Token symbol: ZELDA
	"""

def bip32_path_big_endian_encoded():
	# return b"\x80000002" + struct.pack(">I", 1, 3)
	return bytes.fromhex("800000020000000100000003")


# The private key for BIP32 path: <44'/536'/2'/1/3>
# using mnemonic: <equip will roof matter pink blind book anxiety banner elbow sun young>
def alice_private_key():
	return "f423ae3097703022b86b87c15424367ce827d11676fae5c7fe768de52d9cce2e"

# ByteInterval of the following fields in the following order:
# [
# 	  addressByteInterval,
# 	  amountByteInterval,
# 	  serializerByteInterval,
# 	  tokenDefinitionReferenceByteInterval
# ]
def particle_meta_data():
	return "01e600290216002302ae002602ee003d0379002903a90023044100260481003d06d6002907060023079e002607de003d0869002908990023093100260971003d0d5900290d8900230e2100260e61003d0eec00290f1c00230fb400260ff4003d107f002910af0023114700261187003d000000000000000012f8001800000000"

def atom_6_transfP_1_message_part_by_alice():
	return "bf686d65746144617461bf6974696d657374616d706d31353930343135363933303037ff6e7061727469636c6547726f75707384bf697061727469636c657383bf687061727469636c65bf676164647265737358270402026d5e07cfde5df84b5ef884b629d28d15b0f6c66be229680699767cd57c6182882a49dc3466616d6f756e7458210500000000000000000000000000000000000000000000000000000000000003e86c64657374696e6174696f6e7381510205f1e0f9fa6f2922f14827be92d0a2a06b6772616e756c61726974795821050000000000000000000000000000000000000000000000000000000000000001656e6f6e63650066706c616e636b1a019561046a73657269616c697a6572782472616469782e7061727469636c65732e7472616e736665727261626c655f746f6b656e737818746f6b656e446566696e6974696f6e5265666572656e6365583b062f4a45796f4b4e455961774a6b4e5469696e5168316852396333463537414e697879425269396673534566476564756d696666522f5a454c44416776657273696f6e1864ff6a73657269616c697a65727372616469782e7370756e5f7061727469636c65647370696e206776657273696f6e1864ffbf687061727469636c65bf67616464726573735827040202c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee57f51ade766616d6f756e7458210500000000000000000000000000000000000000000000000000000000000000016c64657374696e6174696f6e73815102e142e5bb89503e3210b1f2c893eb5c126b6772616e756c61726974795821050000000000000000000000000000000000000000000000000000000000000001656e6f6e63650066706c616e636b1a019561046a73657269616c697a6572782472616469782e7061727469636c65732e7472616e736665727261626c655f746f6b656e737818746f6b656e446566696e6974696f6e5265666572656e6365583b062f4a45796f4b4e455961774a6b4e5469696e5168316852396333463537414e697879425269396673534566476564756d696666522f5a454c44416776657273696f6e1864ff6a73657269616c697a65727372616469782e7370756e5f7061727469636c65647370696e016776657273696f6e1864ffbf687061727469636c65bf676164647265737358270402026d5e07cfde5df84b5ef884b629d28d15b0f6c66be229680699767cd57c6182882a49dc3466616d6f756e7458210500000000000000000000000000000000000000000000000000000000000003e76c64657374696e6174696f6e7381510205f1e0f9fa6f2922f14827be92d0a2a06b6772616e756c61726974795821050000000000000000000000000000000000000000000000000000000000000001656e6f6e63650066706c616e636b1a019561046a73657269616c697a6572782472616469782e7061727469636c65732e7472616e736665727261626c655f746f6b656e737818746f6b656e446566696e6974696f6e5265666572656e6365583b062f4a45796f4b4e455961774a6b4e5469696e5168316852396333463537414e697879425269396673534566476564756d696666522f5a454c44416776657273696f6e1864ff6a73657269616c697a65727372616469782e7370756e5f7061727469636c65647370696e016776657273696f6e1864ff6a73657269616c697a65727472616469782e7061727469636c655f67726f75706776657273696f6e1864ffbf697061727469636c657383bf687061727469636c65bf676164647265737358270402026d5e07cfde5df84b5ef884b629d28d15b0f6c66be229680699767cd57c6182882a49dc3466616d6f756e7458210500000000000000000000000000000000000000000000000000000000000003e86c64657374696e6174696f6e7381510205f1e0f9fa6f2922f14827be92d0a2a06b6772616e756c61726974795821050000000000000000000000000000000000000000000000000000000000000001656e6f6e63650066706c616e636b1a019561046a73657269616c697a6572782472616469782e7061727469636c65732e7472616e736665727261626c655f746f6b656e737818746f6b656e446566696e6974696f6e5265666572656e6365583b062f4a45796f4b4e455961774a6b4e5469696e5168316852396333463537414e697879425269396673534566476564756d696666522f5a454c44416776657273696f6e1864ff6a73657269616c697a65727372616469782e7370756e5f7061727469636c65647370696e206776657273696f6e1864ffbf687061727469636c65bf67616464726573735827040202f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f925dbba8c66616d6f756e7458210500000000000000000000000000000000000000000000000000000000000000026c64657374696e6174696f6e7381510242ca0ec5e59f054eaabea5c37335bb096b6772616e756c61726974795821050000000000000000000000000000000000000000000000000000000000000001656e6f6e63650066706c616e636b1a019561046a73657269616c697a6572782472616469782e7061727469636c65732e7472616e736665727261626c655f746f6b656e737818746f6b656e446566696e6974696f6e5265666572656e6365583b062f4a45796f4b4e455961774a6b4e5469696e5168316852396333463537414e697879425269396673534566476564756d696666522f5a454c44416776657273696f6e1864ff6a73657269616c697a65727372616469782e7370756e5f7061727469636c65647370696e016776657273696f6e1864ffbf687061727469636c65bf676164647265737358270402026d5e07cfde5df84b5ef884b629d28d15b0f6c66be229680699767cd57c6182882a49dc3466616d6f756e7458210500000000000000000000000000000000000000000000000000000000000003e66c64657374696e6174696f6e7381510205f1e0f9fa6f2922f14827be92d0a2a06b6772616e756c61726974795821050000000000000000000000000000000000000000000000000000000000000001656e6f6e63650066706c616e636b1a019561046a73657269616c697a6572782472616469782e7061727469636c65732e7472616e736665727261626c655f746f6b656e737818746f6b656e446566696e6974696f6e5265666572656e6365583b062f4a45796f4b4e455961774a6b4e5469696e5168316852396333463537414e697879425269396673534566476564756d696666522f5a454c44416776657273696f6e1864ff6a73657269616c697a65727372616469782e7370756e5f7061727469636c65647370696e016776657273696f6e1864ff6a73657269616c697a65727472616469782e7061727469636c655f67726f75706776657273696f6e1864ffbf697061727469636c657383bf687061727469636c65bf676164647265737358270402026d5e07cfde5df84b5ef884b629d28d15b0f6c66be229680699767cd57c6182882a49dc3466616d6f756e7458210500000000000000000000000000000000000000000000000000000000000003e86c64657374696e6174696f6e7381510205f1e0f9fa6f2922f14827be92d0a2a06b6772616e756c61726974795821050000000000000000000000000000000000000000000000000000000000000001656e6f6e63650066706c616e636b1a019561046a73657269616c697a6572782472616469782e7061727469636c65732e7472616e736665727261626c655f746f6b656e737818746f6b656e446566696e6974696f6e5265666572656e6365583b062f4a45796f4b4e455961774a6b4e5469696e5168316852396333463537414e697879425269396673534566476564756d696666522f5a454c44416776657273696f6e1864ff6a73657269616c697a65727372616469782e7370756e5f7061727469636c65647370696e206776657273696f6e1864ffbf687061727469636c65bf67616464726573735827040202e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13fdc26f8866616d6f756e7458210500000000000000000000000000000000000000000000000000000000000000036c64657374696e6174696f6e73815102d761b817b7111bd27701a8f1ea60d3896b6772616e756c61726974795821050000000000000000000000000000000000000000000000000000000000000001656e6f6e63650066706c616e636b1a019561046a73657269616c697a6572782472616469782e7061727469636c65732e7472616e736665727261626c655f746f6b656e737818746f6b656e446566696e6974696f6e5265666572656e6365583b062f4a45796f4b4e455961774a6b4e5469696e5168316852396333463537414e697879425269396673534566476564756d696666522f5a454c44416776657273696f6e1864ff6a73657269616c697a65727372616469782e7370756e5f7061727469636c65647370696e016776657273696f6e1864ffbf687061727469636c65bf676164647265737358270402026d5e07cfde5df84b5ef884b629d28d15b0f6c66be229680699767cd57c6182882a49dc3466616d6f756e7458210500000000000000000000000000000000000000000000000000000000000003e56c64657374696e6174696f6e7381510205f1e0f9fa6f2922f14827be92d0a2a06b6772616e756c61726974795821050000000000000000000000000000000000000000000000000000000000000001656e6f6e63650066706c616e636b1a019561046a73657269616c697a6572782472616469782e7061727469636c65732e7472616e736665727261626c655f746f6b656e737818746f6b656e446566696e6974696f6e5265666572656e6365583b062f4a45796f4b4e455961774a6b4e5469696e5168316852396333463537414e697879425269396673534566476564756d696666522f5a454c44416776657273696f6e1864ff6a73657269616c697a65727372616469782e7370756e5f7061727469636c65647370696e016776657273696f6e1864ff6a73657269616c697a65727472616469782e7061727469636c655f67726f75706776657273696f6e1864ffbf697061727469636c657381bf687061727469636c65bf65627974657357014f70656e2074686520706f642062617920646f6f72736c64657374696e6174696f6e7382510205f1e0f9fa6f2922f14827be92d0a2a05102b66146757bca0b4fc65cb3aed37a0e3d6466726f6d58270402026d5e07cfde5df84b5ef884b629d28d15b0f6c66be229680699767cd57c6182882a49dc34656e6f6e63651b000001724c1e87776a73657269616c697a65727772616469782e7061727469636c65732e6d65737361676562746f58270402022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4c58f581e6776657273696f6e1864ff6a73657269616c697a65727372616469782e7370756e5f7061727469636c65647370696e016776657273696f6e1864ff6a73657269616c697a65727472616469782e7061727469636c655f67726f75706776657273696f6e1864ff6776657273696f6e1864ff"

def apduPrefix():
	# https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
	CLA = bytes.fromhex("AA")
	INS = b"\x02" # `02` is sign atom
	P1 = b"\x08" # 8 UP particles
	P2 = b"\x00"

	return CLA + INS + P1 + P2


def send_large_atom_to_ledger_in_many_chunks():

	STREAM_LEN = 255 # Stream in batches of STREAM_LEN bytes each.
	bip32Bytes = bip32_path_big_endian_encoded()
	particlesMetaDataBytes = bytearray.fromhex(particle_meta_data())
	atomBytes = bytearray.fromhex(atom_6_transfP_1_message_part_by_alice())

	atomByteCount = len(atomBytes)

	print("atomByteCount: " + str(atomByteCount))

	atomByteCountEncoded = struct.pack(">h", atomByteCount) # `>` means big endian, `h` means `short` -> 2 bytes
	print("atomByteCountEncoded: " + atomByteCountEncoded.hex())

	prefix = apduPrefix()

	payload = bip32Bytes + atomByteCountEncoded + particlesMetaDataBytes

	print("Sending payload: " + payload.hex())

	L_c = bytes([len(payload)])
	apdu = prefix + L_c + payload

	dongle = getDongle(True)
	result = dongle.exchange(apdu)

	numberOfBytesThatHaveBeenSentToLedger = 0

	chunkIndex = 0
	numberOfChunksToSend = int(math.ceil(atomByteCount / STREAM_LEN))
	print(f"Atom will be sent in #chunks: {numberOfChunksToSend}")

	atomBytesChunked = atomBytes.copy()

	# Keep streaming data into the device till we run out of it.
	while numberOfBytesThatHaveBeenSentToLedger < atomByteCount:
		print(f"Sending chunk {chunkIndex+1}/{numberOfChunksToSend}")
		numberOfBytesLeftToSend = atomByteCount - numberOfBytesThatHaveBeenSentToLedger

		chunk = bytearray(0)
		if numberOfBytesLeftToSend > STREAM_LEN:
			chunk = atomBytesChunked[0:STREAM_LEN]
			atomBytesChunked = atomBytesChunked[STREAM_LEN:]
		else:
			chunk = atomBytesChunked
			atomBytesChunked = bytearray(0)

		chunkSize = len(chunk)
		print(f"Chunk {chunkIndex+1}: [{numberOfBytesThatHaveBeenSentToLedger}-{numberOfBytesThatHaveBeenSentToLedger+chunkSize}]") # has size: {chunkSize}, bytes: {chunk.hex()}")
		# hasher.update(chunk)
		# print(f"Expected hasher state after chunk {chunkIndex+1}: {hasher.hexdigest()}")
		L_c = bytes([chunkSize])
		numberOfBytesThatHaveBeenSentToLedger += chunkSize
		apdu = prefix + L_c + chunk
		result = dongle.exchange(apdu)
		chunkIndex += 1
		print(f"numberOfBytesThatHaveBeenSentToLedger: {numberOfBytesThatHaveBeenSentToLedger}, atomByteCount: {atomByteCount}")

	firstHasher = sha256()
	firstHasher.update(atomBytes)
	secondHasher = sha256()
	secondHasher.update(firstHasher.digest())
	expectedSha256TwiceHashOfAtom = secondHasher.hexdigest()
	hashFromLedger = result.hex()

	print(f"Response: {hashFromLedger}")
	print(f"Expected hash: {expectedSha256TwiceHashOfAtom}")
	if expectedSha256TwiceHashOfAtom == hashFromLedger:
		print("Awesome! Hash from ledger matches expected hash")
	else:
		print("Bah! Something is wrong with the hash")
	# print("Length: " + str(len(result)))

	print("Expected to to parse these transfers:\n")
	print(expected_printed_output())

if __name__ == "__main__":
	# parser = argparse.ArgumentParser()
	#parser.add_argument('--txnJson', '-j', type=str, required=False)
	# parser.add_argument('--index', '-i', type=int, required=True)
	# args = parser.parse_args()
	send_large_atom_to_ledger_in_many_chunks()
