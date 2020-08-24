#!/usr/bin/env python3

from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
from typing import List
import argparse
import struct
import math
import binascii
import json
import hashlib
import glob
import os
import time
from pathlib import Path

CommExceptionUserRejection = 0x6985


class TestVector(object):
	def __init__(self, dict):
		self.__dict__ = dict #json.loads(j)

	def expectedUncompressedEphemeralPublicKey_hex(self) -> str:
		return self.__dict__['expectedUncompressedEphemeralPublicKey']

	def expectedCompressedEphemeralPublicKey_hex(self) -> str:
		return self.__dict__['expectedCompressedEphemeralPublicKey']

	def fullECIESEncryptionText_hex(self) -> str:
		return self.__dict__['fullECIESEncryptionText']

	def fullECIESEncryptionText_bytearray(self) -> bytearray:
		return bytearray.fromhex(self.fullECIESEncryptionText_hex())

	def cipherText_just_cipher_hex(self) -> str:
		return self.__dict__['cipherText']

	def cipherText_just_cipher_bytearray(self) -> bytearray:
		return bytearray.fromhex(self.cipherText_just_cipher_hex())

	def cipherText_just_cipher_length(self) -> int:
		return len(self.cipherText_just_cipher_bytearray())

	def MAC_hex(self) -> str:
		return self.__dict__['MAC']

	def MAC_bytearray(self) -> bytearray:
		return bytearray.fromhex(self.MAC_hex())

	def MAC_length(self) -> int:
		return len(self.MAC_bytearray())

	def IV_hex(self) -> str:
		return self.__dict__['IV']

	def IV_bytearray(self) -> bytearray:
		return bytearray.fromhex(self.IV_hex())

	def IV_length(self) -> int:
		return len(self.IV_bytearray())

	def bip32Path_hex(self) -> str:
		return self.__dict__['bip32Path']

	def bip32Path_bytearray(self) -> bytearray:
		return bytearray.fromhex(self.bip32Path_hex())

	def expectedUncompressedEphemeralPublicKey_bytearray(self) -> bytearray:
		return bytearray.fromhex(self.expectedUncompressedEphemeralPublicKey_hex())

	def ephemeralPubKey_length(self) -> int:
		return len(self.expectedUncompressedEphemeralPublicKey_bytearray())

	def expected_plainText(self) -> str:
		return self.__dict__['expectedPlainText']

	def apdu_prefix(self) -> bytearray:
		CLA = bytes.fromhex("AA")
		INS = b"\x16" # `16` is command "DECRYPT"
		p1_not_encoded = len(self.fullECIESEncryptionText_bytearray())
		print(f"p1_not_encoded: {p1_not_encoded}")
		P1 = struct.pack(">B", p1_not_encoded)
		P2 = b"\x00"

		return CLA + INS + P1 + P2

def ecies_decrypt(dongle, vector: TestVector) -> bool:
	# message_for_mac = vector.IV_hex() + vector.expectedCompressedEphemeralPublicKey_hex() + vector.cipherText_just_cipher_hex()
	print(f"""
	🚀 vector:
	PlainText: '{vector.expected_plainText()}'
	💉IV: {vector.IV_hex()}
	🔑ephemeralPublicKey uncompressed: {vector.expectedUncompressedEphemeralPublicKey_hex()}
	🔐cipher: {vector.cipherText_just_cipher_hex()}
	
	💻 MAC: {vector.MAC_hex()}
	FULL encrypted: {vector.fullECIESEncryptionText_hex()}

	🔮

	""")

	# 	Message for MAC:{message_for_mac}

	prefix = vector.apdu_prefix()

	# BIPPath(12) || IV(16) || EphemeralPubKeyUncomp(65) || CipherText(P1) || MAC(32) 
	assert vector.IV_length() == 16
	assert vector.ephemeralPubKey_length() == 65
	assert vector.MAC_length() == 32
	# payload = vector.bip32Path_bytearray() + vector.IV_bytearray() + vector.expectedUncompressedEphemeralPublicKey_bytearray() + vector.cipherText_just_cipher_bytearray() + vector.MAC_bytearray()
	payload = vector.bip32Path_bytearray() + vector.fullECIESEncryptionText_bytearray()

	print(f"payload: {payload.hex()}")

	payload_size = len(payload)
	
	assert payload_size <= 255, "Max bytes to send is 255"

	L_c = bytes([payload_size])
	apdu = prefix + L_c + payload


	print(f"Sending APDU: {apdu.hex()}")
	result = dongle.exchange(apdu)
	print(f"Hex result from dongle: {result.hex()}")
	plainText_from_ledger = result.decode('utf8')
	expectedPlainText = vector.expected_plainText()

	if plainText_from_ledger == expectedPlainText:
		print(f"\n✅ Awesome! Plain text from ledger matches that from Java library ✅\nPlainText: {plainText_from_ledger}")
	else:
		print("\n ☢️ PLain text mismatch ☢️\n")
		print(f"Expected plainText: {expectedPlainText}") 
		print(f"But got plainText from ledger: {plainText_from_ledger}")
		return False

	print("💡 done with this vector...")
	return True


if __name__ == "__main__":
	json_filepath = os.path.join('.', 'vectors', 'ecies', 'ecies_decrypt_vectors.json')


	letDongleOutputDebugPrintStatements = False
	dongle = getDongle(debug=letDongleOutputDebugPrintStatements)

	with open(json_filepath, 'r') as json_file:
		json_array_of_vectors = json.load(json_file)
		success_count = 0
		for vector_json in json_array_of_vectors:
			vector = TestVector(vector_json)
			if ecies_decrypt(dongle, vector):
				success_count += 1
			print("sleeping 1 second...")
			time.sleep(1)
			print("Wook up after having slept")

		print(f"Success count: {success_count}")
		assert success_count == len(json_array_of_vectors), "Expected all vectors to pass"

	dongle.close()
	print("⭐️ DONE! ⭐️")
