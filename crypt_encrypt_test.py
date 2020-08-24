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

	def keyE_hex(self) -> str:
		return self.__dict__['keyE']

	def keyE_bytearray(self) -> bytearray:
		return bytearray.fromhex(self.keyE_hex())

	def data_hex(self) -> str:
		return self.__dict__['data']

	def data_bytearray(self) -> bytearray:
		return bytearray.fromhex(self.data_hex())

	def iv_hex(self) -> str:
		return self.__dict__['iv']

	def iv_bytearray(self) -> bytearray:
		return bytearray.fromhex(self.iv_hex())

	def expectedCipherText_hex(self) -> str:
		return self.__dict__['encryptedData']

	def apdu_prefix(self) -> bytearray:
		CLA = bytes.fromhex("AA")
		INS = b"\x16" # `16` is command "ENCRYPT_OR_DECRYPT"
		P1 = struct.pack(">B", len(self.data_bytearray()))
		P2 = struct.pack(">B", len(self.iv_bytearray()))

		return CLA + INS + P1 + P2

def crypt_encrypt(dongle, vector: TestVector) -> bool:
	print(f"🚀 vector:\niv: {vector.iv_hex()}\nkeyE: {vector.keyE_hex()}\ndata: {vector.data_hex()}\n🧩\n")

	prefix = vector.apdu_prefix()

	payload = vector.data_bytearray() + vector.iv_bytearray() + vector.keyE_bytearray()
	print(f"payload: {payload.hex()}")

	payload_size = len(payload)
	
	assert payload_size <= 255, "Max bytes to send is 255"

	L_c = bytes([payload_size])
	apdu = prefix + L_c + payload


	print(f"Sending APDU: {apdu.hex()}")
	result = dongle.exchange(apdu)

	cipherText_from_ledger_hex = result.hex()
	expected_cipherText_hex = vector.expectedCipherText_hex()

	if cipherText_from_ledger_hex == expected_cipherText_hex:
		print(f"\n✅ Awesome! Cipher text from ledger matches that from Java library ✅\nCipher: {cipherText_from_ledger_hex}")
	else:
		print("\n ☢️ Cipher text mismatch ☢️\n")
		print(f"Expected cipherText: {expected_cipherText_hex}") 
		print(f"But got cipherText from ledger: {cipherText_from_ledger_hex}")
		return False

	print("💡 done with this vector...")
	return True


if __name__ == "__main__":
	# json_filepath = Path('./vectors/crypt/crypt_aes_cbc_vectors.json')
	json_filepath = os.path.join('.', 'vectors', 'crypt', 'crypt_aes_cbc_vectors.json')


	letDongleOutputDebugPrintStatements = False
	dongle = getDongle(debug=letDongleOutputDebugPrintStatements)

	with open(json_filepath, 'r') as json_file:
		json_array_of_vectors = json.load(json_file)
		success_count = 0
		for vector_json in json_array_of_vectors:
			vector = TestVector(vector_json)
			if crypt_encrypt(dongle, vector):
				success_count += 1
			print("sleeping 1 second...")
			time.sleep(1)
			print("Wook up after having slept")

		print(f"Success count: {success_count}")
		assert success_count == len(json_array_of_vectors), "Expected all vectors to pass"

	dongle.close()
	print("⭐️ DONE! ⭐️")
