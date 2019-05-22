import struct
import base58
import hashlib
import ecdsa
import codecs

import sys

print("Enter privateKey for the user that generate the Tx:")
Bob_private_key = sys.stdin.readline()[:-1]
print("Enter Address for the user that generate the Tx:")
Bob_addr = sys.stdin.readline()[:-1]
print("Enter the TxId for the imput:")
prv_txid = sys.stdin.readline()[:-1]
assert len(prv_txid) == 64
outputs = []
while (True):
    print("Enter BitcoinAddress for an output or end:")
    outputAddr = sys.stdin.readline()[:-1]
    if outputAddr == 'end':
        break
    print("Enter Bitcoin to send to the output:")
    outputBitcoins = sys.stdin.readline()[:-1]
    outputs.append([outputAddr, int(float(outputBitcoins) * 100000000)])

bob_hashed_pubkey = codecs.encode(base58.b58decode_check(Bob_addr)[1:], 'hex_codec')


class raw_tx:
    version = struct.pack("<L", 1)
    tx_in_count = struct.pack("<B", 1)
    tx_in = {}  # TEMP
    tx_out_count = struct.pack("<B", len(outputs))
    tx_out1 = {}  # TEMP
    tx_out2 = {}  # TEMP
    lock_time = struct.pack("<L", 0)


def flip_byte_order(string):
    flipped = "".join(reversed([string[i:i + 2] for i in range(0, len(string), 2)]))
    return flipped


rtx = raw_tx()

rtx.tx_in["txouthash"] = bytes.fromhex(flip_byte_order(prv_txid))
rtx.tx_in["tx_out_index"] = struct.pack("<L", 0)
rtx.tx_in["script"] = bytes.fromhex(('76a914{}88ac'.format(bob_hashed_pubkey.decode("utf-8"))))
rtx.tx_in["scrip_bytes"] = struct.pack("<B", len(rtx.tx_in["script"]))
rtx.tx_in["sequence"] = bytes.fromhex("ffffffff")
outputs_ready = []

output_tx_string = ""
for output in outputs:
    value = struct.pack("<Q", output[1])
    out_hashed_pubkey = codecs.encode(base58.b58decode_check(output[0])[1:], 'hex_codec')
    pk_script = bytes.fromhex(('76a914{}88ac'.format(out_hashed_pubkey.decode("utf-8"))))
    pk_script_bytes = struct.pack("<B", len(pk_script))
    output_tx_string = output_tx_string + value.hex() + pk_script_bytes.hex() + pk_script.hex()

raw_tx_string = (

        rtx.version
        + rtx.tx_in_count
        + rtx.tx_in["txouthash"]
        + rtx.tx_in["tx_out_index"]
        + rtx.tx_in["scrip_bytes"]
        + rtx.tx_in["script"]
        + rtx.tx_in["sequence"]
        + rtx.tx_out_count
        + bytes.fromhex(output_tx_string)
        + rtx.lock_time
        + struct.pack("<L", 1)

)

hashed_tx_to_sign = hashlib.sha256(hashlib.sha256(raw_tx_string).digest()).digest()

sk = ecdsa.SigningKey.from_string(bytes.fromhex(Bob_private_key), curve=ecdsa.SECP256k1)

vk = sk.verifying_key

public_key = '04' + vk.to_string().hex()
signature = sk.sign_digest(hashed_tx_to_sign, sigencode=ecdsa.util.sigencode_der_canonize)

sigscript = (

        signature.hex()
        + "01"
        + struct.pack("<B", len(bytes.fromhex(public_key))).hex()
        + public_key

)

real_tx = (
        rtx.version
        + rtx.tx_in_count
        + rtx.tx_in["txouthash"]
        + rtx.tx_in["tx_out_index"]
        + struct.pack("<B", len(bytes.fromhex(sigscript)) + 1)
        + struct.pack("<B", len(signature) + 1)
        + bytes.fromhex(sigscript)
        + rtx.tx_in["sequence"]
        + rtx.tx_out_count
        + bytes.fromhex(output_tx_string)
        + rtx.lock_time

)

print(real_tx.hex())
