#!/usr/bin/python3

# Copyright (C) 2014 The python-bitcoinlib developers
#
# This file is part of python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

"""Low-level example of how to spend a standard pay-to-pubkey-hash (P2PKH) txout"""

import sys
if sys.version_info.major < 3:
    sys.stderr.write('Sorry, Python 3.x required by this example.\n')
    sys.exit(1)

import hashlib
from bitcoin import SelectParams
from bitcoin.core import b2x, lx, COIN, COutPoint, CMutableTxOut, CMutableTxIn, CMutableTransaction, Hash160, x, Hash
from bitcoin.core.script import CScript, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, SignatureHash, SIGHASH_ALL
from bitcoin.core.scripteval import VerifyScript, SCRIPT_VERIFY_P2SH
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret

SelectParams('mainnet')

# Create the (in)famous correct brainwallet secret key.
h = hashlib.sha256(b'correct horse battery staple').digest()
hexKey = "0ecd20654c2e2be708495853e8da35c664247040c00bd10b9b13e5e86e6a808d"
seckey = CBitcoinSecret.from_secret_bytes(x(hexKey))
print(seckey.hex())
print(b2x( Hash160(seckey.pub)))
print('dd6cce9f255a8cc17bda8ba0373df8e861cb866e')
# Same as the txid:vout the createrawtransaction RPC call requires
#
# lx() takes *little-endian* hex and converts it to bytes; in Bitcoin
# transaction hashes are shown little-endian rather than the usual big-endian.
# There's also a corresponding x() convenience function that takes big-endian
# hex and converts it to bytes.
txid = x('be66e10da854e7aea9338c1f91cd489768d1d6d7189f586d7a3613f2a24d5396')
vout = 0

# Create the txin structure, which includes the outpoint. The scriptSig
# defaults to being empty.
txin = CMutableTxIn(COutPoint(txid, vout))

# We also need the scriptPubKey of the output we're spending because
# SignatureHash() replaces the transaction scriptSig's with it.
#
# Here we'll create that scriptPubKey from scratch using the pubkey that
# corresponds to the secret key we generated above.
txin_scriptPubKey = CScript([OP_DUP, OP_HASH160, Hash160(seckey.pub), OP_EQUALVERIFY, OP_CHECKSIG])

# Create the txout. This time we create the scriptPubKey from a Bitcoin
# address.
#txout = CMutableTxOut(118307, CBitcoinAddress('1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8').to_scriptPubKey())
txout = CMutableTxOut(118307, x('76a9142bc89c2702e0e618db7d59eb5ce2f0f147b4075488ac'))

# Create the unsigned transaction.
tx = CMutableTransaction([txin], [txout])

# Calculate the signature hash for that transaction.
sighash = SignatureHash(txin_scriptPubKey, tx, 0, SIGHASH_ALL)

# Now sign it. We have to append the type of signature we want to the end, in
# this case the usual SIGHASH_ALL.
sig = seckey.sign(sighash) + bytes([SIGHASH_ALL])

# Set the scriptSig of our transaction input appropriately.
txin.scriptSig = CScript([sig, seckey.pub])

# Verify the signature worked. This calls EvalScript() and actually executes
# the opcodes in the scripts to see if everything worked out. If it doesn't an
# exception will be raised.
worked = VerifyScript(txin.scriptSig, txin_scriptPubKey, tx, 0, (SCRIPT_VERIFY_P2SH,))

# Done! Print the transaction to standard output with the bytes-to-hex
# function.
print("Script response: {}".format(b2x(tx.serialize())))
serialization = b2x(tx.serialize()) + '01000000'
print(serialization)
h1 = x(serialization)
print(b2x(Hash(h1)))
