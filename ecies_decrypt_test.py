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
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
from pathlib import Path
from fastecdsa import keys, curve as curve_, ecdsa
from fastecdsa.point import Point as ECPoint
from fastecdsa.encoding.sec1 import SEC1Encoder
# from hashlib import sha256, sha512
import hashlib


CommExceptionUserRejection = 0x6985

# STREAM encrypt and decrypt (from year 2019): https://github.com/eliben/code-for-blog/blob/master/2010/aes-encrypt-pycrypto/pycrypto_file.py

secp256k1 = curve_.secp256k1

# def EC_secp256k1_point_mult(scalar, point_bytes) -> ECPoint:

# 	# message = b'Hello, World!'
# 	# privkey, pubkey = keys.gen_keypair(curve=curve)
# 	# sign = ecdsa.sign(message, privkey, curve=curve, hashfunc=sha3_256)
# 	assert len(point_bytes) == 64
# 	point = Point(point_bytes[:32], point_bytes[32:64], curve=secp256k1)
# 	pointM = scalar * point  
# 	return pointM

# def EC_secp256k1_point_mult(scalar, point) -> ECPoint:

# 	# message = b'Hello, World!'
# 	# privkey, pubkey = keys.gen_keypair(curve=curve)
# 	# sign = ecdsa.sign(message, privkey, curve=curve, hashfunc=sha3_256)
# 	# assert len(point_bytes) == 64
# 	# point = Point(point_bytes[:32], point_bytes[32:64], curve=secp256k1)
# 	pointM = scalar * point  
# 	return pointM

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
		return self.__dict__['bip32Path']

	def bip32Path(self) -> bytearray:
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

	def __iv(self) -> bytearray:
		return self.encryped_message()[:16]

	def __ephemeral_public_key_compressed(self) -> bytearray:
		start_index = 16 + 1
		length = 33
		end_index = start_index + length
		pubKeyCompBytes = self.encryped_message()[start_index:end_index]
		print(f"pubKeyBytes: {pubKeyCompBytes}")
		return pubKeyCompBytes

	def __ephemeral_public_key_point(self) -> ECPoint:
		return SEC1Encoder.decode_public_key(
			self.__ephemeral_public_key_compressed(),
			secp256k1
		)

	def __hashH(self) -> bytearray:
		alicePrivateKey = 0xf423ae3097703022b86b87c15424367ce827d11676fae5c7fe768de52d9cce2e
		point = self.__ephemeral_public_key_point()
		print("🔮 performing EC mult")
		pointM = point * alicePrivateKey
		print("🧩 EC mult done")
		print(f"pointM: {pointM}")
		hashH = sha512_twice(pointM.x.to_bytes(32, 'big'))
		print(f"hashH: {hashH}")
		return hashH

	def __keyE(self) -> bytearray:
		return self.__hashH()[:32]

	def __cipher_length(self) -> int:
		start_index = 16 + 1 + 33
		length = 4
		end_index = start_index + length
		length_bytes = self.encryped_message()[start_index:end_index]
		length = struct.unpack(">I", length_bytes)[0]
		print(f"cipher length: {length}")
		return length

	def __cipher(self) -> bytearray:
		start_index = 16 + 1 + 33 + 4
		length = self.__cipher_length()
		end_index = start_index + length
		return self.encryped_message()[start_index:end_index]

	def __mac(self) -> bytearray:
		return self.encryped_message()[-32]

	def ecies_decrypt(self) -> str:
		IV = self.__iv()
		mode = AES.MODE_CBC
		key = self.__keyE()
		decryptor = AES.new(key, mode, IV=IV)
		cipherText = self.__cipher()
		plain = unpad(decryptor.decrypt(cipherText), block_size=16, style='pkcs7')
		plainText = str(plain,'utf-8')
		return plainText

def ecies_decrypt(dongle, vector: TestVector) -> bool:
	print(f"""

🚀 vector:
🔓Expected plain text: '{vector.expected_plainText()}'
🔐Encrypted msg: '{vector.encryped_message_hex()}'
🔓Decrypted msg: '{vector.ecies_decrypt()}'
🔮""")

	os._exit(-1337)

	prefix = vector.apdu_prefix()

	# BIPPath(12) || EncrypedMessage
	payload = vector.bip32Path() + vector.encryped_message()

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
