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

	def cipherText_hex(self) -> str:
		return self.__dict__['cipherText']

	def cipherText_bytearray(self) -> bytearray:
		return bytearray.fromhex(self.cipherText_hex())

	def cipherText_length(self) -> int:
		return len(self.cipherText_bytearray())

	def bip32Path_hex(self) -> str:
		return self.__dict__['bip32Path']

	def bip32Path_bytearray(self) -> bytearray:
		return bytearray.fromhex(self.bip32Path_hex())

	def expected_plainText(self) -> str:
		return self.__dict__['expectedPlainText']

	def apdu_prefix(self) -> bytearray:
		CLA = bytes.fromhex("AA")
		INS = b"\x16" # `16` is command "DECRYPT"
		P1 = struct.pack(">B", self.cipherText_length())
		P2 = b"\x00"

		return CLA + INS + P1 + P2

def ecies_decrypt(dongle, vector: TestVector) -> bool:
	print(f"🚀 vector:\nPlainText: '{vector.expected_plainText()}', ephemeralPublicKey:\n🔑 uncompressed: {vector.expectedUncompressedEphemeralPublicKey_hex()},\n🔑 compressed: {vector.expectedCompressedEphemeralPublicKey_hex()}\n🔮\n")

	prefix = vector.apdu_prefix()

	payload = vector.bip32Path_bytearray() + vector.cipherText_bytearray()
	print(f"payload: {payload.hex()}")

	payload_size = len(payload)
	
	assert payload_size <= 255, "Max bytes to send is 255"

	L_c = bytes([payload_size])
	apdu = prefix + L_c + payload


	print(f"Sending APDU: {apdu.hex()}")
	result = dongle.exchange(apdu)

	plainTextEnc_from_ledger_hex = result.hex()
	plainText_from_ledger = plainTextEnc_from_ledger_hex.decode('utf8')
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
