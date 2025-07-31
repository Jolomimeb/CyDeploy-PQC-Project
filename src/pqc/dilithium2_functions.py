# dilithium2_functions.py - Dilithium2 signature utilities
# Provides functions to generate Dilithium2 keypairs, sign, and verify.
# dillithium2 is basicall Ml_dsa_44 parameter
from dilithium_py.dilithium import Dilithium2

def generate_keys():
    """Generate a Dilithium2 public/private keypair."""
    pk, sk = Dilithium2.keygen()
    return pk, sk

def sign_message(sk, message: bytes) -> bytes:
    """Sign a message with the Dilithium2 private key."""
    return Dilithium2.sign(sk, message)

def verify_signature(pk, message: bytes, signature: bytes) -> bool:
    """Verify a signature with the Dilithium2 public key."""
    return Dilithium2.verify(pk, message, signature)