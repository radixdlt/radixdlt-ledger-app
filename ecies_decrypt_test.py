#!/usr/bin/env python3

from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
from functools import reduce
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
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
from pathlib import Path
from fastecdsa import keys, curve as curve_, ecdsa
from fastecdsa.point import Point as ECPoint
from fastecdsa.encoding.sec1 import SEC1Encoder
import hashlib


CommExceptionUserRejection = 0x6985

aes256_blocksize = 16

def sha512_twice(data) -> bytearray:
	m = hashlib.sha512()
	m.update(data)
	once = m.digest()
	m = hashlib.sha512()
	m.update(once)
	twice = m.digest()
	return twice


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

	def __ephemeral_public_key_point(self) -> ECPoint:
		return SEC1Encoder.decode_public_key(
			self.ephemeral_public_key_compressed(),
			curve_.secp256k1
		)

	def __hashH(self) -> bytearray:
		alicePrivateKey = 0xf423ae3097703022b86b87c15424367ce827d11676fae5c7fe768de52d9cce2e
		point = self.__ephemeral_public_key_point()
		pointM = point * alicePrivateKey
		hashH = sha512_twice(pointM.x.to_bytes(32, 'big'))
		return hashH

	def __keyE(self) -> bytearray:
		return self.__hashH()[:32]

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

	def ecies_decrypt(self) -> str:
		IV = self.iv()
		key = self.__keyE()
		decryptor = AES.new(key, AES.MODE_CBC, IV=IV)
		cipherText = self.cipher()
		plain = unpad(decryptor.decrypt(cipherText), block_size=16, style='pkcs7')
		plainText = str(plain,'utf-8')
		return plainText

	def stream_decrypt(self, chunksize=240) -> str:
		assert chunksize % aes256_blocksize == 0, "chunksize must be multiple of AES blocksize (16)" 
		IV = self.iv()
		key = self.__keyE()
		decryptor = AES.new(key, AES.MODE_CBC, IV=IV)
		stream = self.cipher()
		decrypted_whole = bytearray()
		
		while True:
			chunk = stream[:chunksize]
			size_of_chunk = len(chunk)
			if size_of_chunk == 0:
				break
			stream = stream[size_of_chunk:len(stream)]
			# print(f"🌸 Chunk: '{chunk}'\n")
		
			decrypted_chunk = decryptor.decrypt(chunk)
			# print(f"🏓 decrypted chunk: {decrypted_chunk}")
			decrypted_whole.extend(decrypted_chunk)

		plain = unpad(decrypted_whole, block_size=aes256_blocksize, style='pkcs7')
		plainText = str(plain,'utf-8')
		return plainText 

def ecies_decrypt(dongle, vector: TestVector) -> bool:
	decypted_python = vector.ecies_decrypt()
	decypted_stream_python = vector.stream_decrypt()

	if decypted_python != decypted_stream_python:
		print("\n☢️ Python ECIES decryption and Stream decryption mismatches ☢️\n")
		print(f"stream: {decypted_stream_python}\n\nnormal: {decypted_python}") 
	else:
		print("\n\n🧩 Awesome STREAM works!!!! 🧩\n")

	print(f"""

🚀 vector:
🔓Expected plain text: '{vector.expected_plainText()}'
🔐Encrypted msg: '{vector.encryped_message_hex()}'
🔓Decrypted msg: '{decypted_python}'
🔓Decrypted stream msg: '{decypted_stream_python}'
🔮""")

	if decypted_python != vector.expected_plainText():
		print("\n☢️ Python ECIES decryption failed ☢️\n")
	else:
		print("\n\n🧩 Awesome plaintexts matches! 🧩\n")

	prefix = vector.apdu_prefix()

	# BIPPath(12) || EncrypedMessage
	pubkey_length_encoded = struct.pack(">B", 33)
	cipher_length_encoded = struct.pack(">i", vector.cipher_length())

	payload = reduce((lambda x, y: bytearray(x) + bytearray(y)), [vector.bip32Path(), vector.iv(), pubkey_length_encoded, vector.ephemeral_public_key_compressed(), cipher_length_encoded, vector.mac()])

	# print(f"payload: {payload.hex()}")

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

		print(f"from ledger RAW: '{result}'\n")
		# payload_response = result[5:]
		# print(f"from ledger drop first 5: '{payload_response}'\n")
		decrypted_whole.extend(result)

		chunk_index += 1

		if chunk_index == chunks_to_stream:
			print(f"🔮 Finished streaming all chunks to the ledger.\n")
	# END of streaming

	print(f"\n🎸\nMessage from ledger:\n'{str(decrypted_whole,'utf-8')}'\n\n")
	plain = unpad(decrypted_whole, block_size=aes256_blocksize, style='pkcs7')
	plainText_from_ledger = str(plain,'utf-8')
	expectedPlainText = vector.expected_plainText()

	if plainText_from_ledger == expectedPlainText:
		print(f"""✅ Awesome! Plain text from ledger matches that from Java library ✅
💡PlainText: '{plainText_from_ledger}'
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
