import os
import ecdsa
import hashlib
import base58
import io
import sys
print("Enter some text to generate private,public, and bitcoin address:")
a = sys.stdin.readline()
private_key = hashlib.sha256(bytes(a, 'utf-8')).hexdigest()

print("this is my private key: " + private_key)

sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve = ecdsa.SECP256k1)

vk = sk.verifying_key

public_key = ('04' + vk.to_string().hex())

print("this is my public key: " + public_key)

ripemd160 = hashlib.new('ripemd160')

ripemd160.update(hashlib.sha256(bytes.fromhex(public_key)).digest())

middle_man = bytes.fromhex('00' + ripemd160.hexdigest())
checksum = hashlib.sha256(hashlib.sha256(middle_man).digest()).digest()[:4]

binary_addr = middle_man + checksum
addr = base58.b58encode(binary_addr)

print("this is my BTC address: " + str(addr,'utf-8'))
