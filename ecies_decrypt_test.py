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


	def encryped_message_hex(self) -> str:
		return self.__dict__['encryptedMessage']

	def encryped_message_bytearray(self) -> bytearray:
		return bytearray.fromhex(self.encryped_message_hex())

	def encrypted_msg_size(self) -> int:
		return len(self.encryped_message_bytearray())

	def bip32Path_hex(self) -> str:
		return self.__dict__['bip32Path']

	def bip32Path_bytearray(self) -> bytearray:
		return bytearray.fromhex(self.bip32Path_hex())


	def expected_plainText(self) -> str:
		return self.__dict__['expectedPlainText']

	def apdu_prefix(self) -> bytearray:
		assert self.encrypted_msg_size() <= 255, "Max encrypted msg size is 255"
		CLA = bytes.fromhex("AA")
		INS = b"\x16" # `16` is command "DECRYPT"
		P1 = struct.pack(">B", self.encrypted_msg_size())
		P2 = b"\x00"

		return CLA + INS + P1 + P2

def ecies_decrypt(dongle, vector: TestVector) -> bool:
	print(f"""

🚀 vector:
🔓Expected plain text: '{vector.expected_plainText()}'
🔐Encrypted msg: {vector.encryped_message_hex()}
🔮""")


	prefix = vector.apdu_prefix()

	# BIPPath(12) || EncrypedMessage
	payload = vector.bip32Path_bytearray() + vector.encryped_message_bytearray()

	# print(f"payload: {payload.hex()}")

	payload_size = len(payload)
	
	assert payload_size <= 255, "Max bytes to send is 255"

	L_c = bytes([payload_size])
	apdu = prefix + L_c + payload


	# print(f"Sending APDU: {apdu.hex()}")
	result = dongle.exchange(apdu)
	# print(f"Hex result from dongle: {result.hex()}")
	plainText_from_ledger = result.decode('utf8')
	expectedPlainText = vector.expected_plainText()

	if plainText_from_ledger == expectedPlainText:
		print(f"""✅ Awesome! Plain text from ledger matches that from Java library ✅
💡PlainText: '{plainText_from_ledger}'
"""
		)

	else:
		print("\n☢️ Plain text mismatch ☢️\n")
		print(f"Expected plainText: {expectedPlainText}") 
		print(f"But got plainText from ledger: {plainText_from_ledger}")
		return False

	# print("💡 done with this vector...")
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
			# print("sleeping 1 second...")
			# time.sleep(1)
			# print("Wook up after having slept")

		print(f"Success count: {success_count}")
		assert success_count == len(json_array_of_vectors), "Expected all vectors to pass"

	dongle.close()
	print("⭐️ DONE! ⭐️")
