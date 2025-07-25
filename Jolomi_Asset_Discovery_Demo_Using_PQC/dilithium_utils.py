# dilithium_utils.py - Dilithium signature utilities
# This module provides functions to:
# 1. Generate Dilithium keypairs.
# 2. Sign messages with a private key.
# 3. Verify signatures with a public key.

from dilithium_py.dilithium import Dilithium2

def generate_keys():
    # Generate a Dilithium public/private keypair
    pk, sk = Dilithium2.keygen()
    return pk, sk

def sign_message(sk, message: bytes) -> bytes:
    # Sign a message with the private key
    return Dilithium2.sign(sk, message)

def verify_signature(pk, message: bytes, signature: bytes) -> bool:
    # Verify a signature with the public key
    return Dilithium2.verify(pk, message, signature)
