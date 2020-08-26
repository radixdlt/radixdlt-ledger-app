#!/usr/bin/env python3

from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException

from functools import reduce
from typing import List

import argparse
import struct
import math
import json
import glob
import os

aes256_blocksize = 16
CommExceptionUserRejection = 0x6985


class TestVector(object):
	def __init__(self, dict):
		self.__dict__ = dict


	def encryped_message_hex(self) -> str:
		"""
		IV(16) + 0x33(1) + PubKey(33) + L_CipherTextLength(4) + CipherText(L) + MAC(32)
		"""
		return self.__dict__['encryptedMessage']

	def encryped_message(self) -> bytearray:
		"""
		IV(16) + 0x33(1) + PubKey(33) + L_CipherTextLength(4) + CipherText(L) + MAC(32)
		"""
		return bytearray.fromhex(self.encryped_message_hex())

	def encrypted_msg_size(self) -> int:
		return len(self.encryped_message())

	def bip32Path_hex(self) -> str:
		# return self.__dict__['bip32Path']
		return "800000020000000100000003"

	def bip32Path(self) -> bytearray:
		return bytearray.fromhex(self.bip32Path_hex())


	def expected_plainText(self) -> str:
		return self.__dict__['expectedPlainText']

	def apdu_prefix(self) -> bytearray:
		CLA = bytes.fromhex("AA")
		INS = b"\x16" # `16` is command "DECRYPT"
		P1 = b"\x00" 
		P2 = b"\x00"

		return CLA + INS + P1 + P2

	def iv(self) -> bytearray:
		return self.encryped_message()[:16]

	def ephemeral_public_key_compressed(self) -> bytearray:
		start_index = 16 + 1
		length = 33
		end_index = start_index + length
		pubKeyCompBytes = self.encryped_message()[start_index:end_index]
		return pubKeyCompBytes

	def cipher_length(self) -> int:
		start_index = 16 + 1 + 33
		length = 4
		end_index = start_index + length
		length_bytes = self.encryped_message()[start_index:end_index]
		length = struct.unpack(">I", length_bytes)[0]
		return length

	def cipher(self) -> bytearray:
		start_index = 16 + 1 + 33 + 4
		length = self.cipher_length()
		end_index = start_index + length
		return self.encryped_message()[start_index:end_index]

	def mac(self) -> bytearray:
		return self.encryped_message()[-32:]

def ecies_decrypt(dongle, vector: TestVector) -> bool:
	print(f"""

🚀 vector:
🔓Expected plain text: '{vector.expected_plainText()}'
🔐Encrypted msg: '{vector.encryped_message_hex()}'
🔮""")

	prefix = vector.apdu_prefix()
	pubkey_length_encoded = struct.pack(">B", 33)
	cipher_length_encoded = struct.pack(">i", vector.cipher_length())
	payload = reduce((lambda x, y: bytearray(x) + bytearray(y)), [vector.bip32Path(), vector.iv(), pubkey_length_encoded, vector.ephemeral_public_key_compressed(), cipher_length_encoded, vector.mac()])


	payload_size = len(payload)
	assert payload_size <= 255, "Max bytes to send is 255"

	L_c = bytes([payload_size])
	apdu = prefix + L_c + payload
	result = dongle.exchange(apdu)


	cipher_byte_count = vector.cipher_length()
	chunksize = 240 # MUST be a multiple of 16, being AES block size
	chunks_to_stream = int(math.ceil(cipher_byte_count / chunksize))
	print(f"Cipher text will be sent in #chunks: {chunks_to_stream}")

	# Keep streaming data into the device till we run out of it.
	stream = vector.cipher()
	decrypted_whole = bytearray()
	chunk_index = 1
	while True:
		chunk = stream[:chunksize]
		size_of_chunk = len(chunk)
		if size_of_chunk == 0:
			break
		stream = stream[size_of_chunk:len(stream)]

		L_c = bytes([chunksize])
		apdu = prefix + L_c + chunk
		
		print(f"Streaming chunk: {chunk_index}/{chunks_to_stream}")

		try:
			result = dongle.exchange(apdu)
		except CommException as commException:
			if commException.sw == CommExceptionUserRejection:
				print("🙅🏿‍♀️ You rejected the msg to decrypt...Aborting vector.")
				dongle.close()
				return False
			else:
				raise commException # unknown error, interrupt exection and propage the error.

		decrypted_whole.extend(result)

		if chunk_index == chunks_to_stream:
			print(f"🔮 Finished streaming all chunks to the ledger.\n")

		chunk_index += 1

	# END of streaming

	plainText_from_ledger = str(decrypted_whole,'utf-8')
	expectedPlainText = vector.expected_plainText()

	if plainText_from_ledger == expectedPlainText:
		print(f"""✅ Awesome! Plain text from ledger matches that from Java library ✅
💡PlainText:\n'{plainText_from_ledger}\n'
""")
	else:
		print("\n☢️ Plain text mismatch ☢️\n")
		print(f"Expected plainText: {expectedPlainText}") 
		print(f"But got plainText from ledger: {plainText_from_ledger}")
		return False

	return True


if __name__ == "__main__":
	json_filepath = os.path.join('.', 'vectors', 'ecies', 'ecies_decrypt_vectors.json')


	letDongleOutputDebugPrintStatements = False
	dongle = getDongle(debug=letDongleOutputDebugPrintStatements)

	with open(json_filepath, 'r') as json_file:
		json_array_of_vectors = json.load(json_file)
		success_count = 0
		fail_count = 0
		for vector_json in json_array_of_vectors:
			vector = TestVector(vector_json)
			if ecies_decrypt(dongle, vector):
				success_count += 1
			else:
				fail_count += 1
		print(f"Success count: {success_count}/{success_count + fail_count}")
		assert success_count == len(json_array_of_vectors), "Expected all vectors to pass"

	dongle.close()
	print("⭐️ DONE! ⭐️")
