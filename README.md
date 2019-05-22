# Exersice 3.10.
Do a raw signature of a Bitcoin transaction as a wallet would do. Note that this is just a
string. You have to be able to explain what part of the signature corresponds to what. You
might have to install a base client for this (without the need to sync the blockchain).

This Python2/3 scripts provides an easy interface to the bitcoin raw a sign transactions string as a wallet way for a p2ps

## Requirements

    install dependecies using:
    pip install -r requirements.txt

The scripts with _p2.py subffix must be used in python2 environment. The rest could be used, in python3 environment.
Same scripts has been provided to both language versions.

## Usage

The keys.py and keys_p2.py generate from a required text form the command linee a public, private, and bitcoin address.


Just run:

    python keys.py

The tx_serialize_p2.py and tx_serialize_p3.py scripts request some information to create and sign a transaction.
The result is a raw transaction signed and ready to be sended to a node in order to be included in a block.


    python tx_serialize_p3.py
