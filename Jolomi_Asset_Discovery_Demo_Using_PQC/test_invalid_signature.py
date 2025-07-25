from sign_inventory import prepare_signed_encrypted_inventory
from dilithium_utils import generate_keys
from key_exchange_utils import generate_kem_keypair, derive_aes_key
import os

if __name__ == "__main__":
    # Tamper with payload to test verification failure

    ek, dk = generate_kem_keypair()
    pk, sk = generate_keys()
    aes_key = derive_aes_key(os.urandom(32))

    # Get legit payload
    legit = prepare_signed_encrypted_inventory(aes_key, sk)

    # Tamper with ciphertext
    tampered = bytearray(legit)
    tampered[-1] ^= 0xFF  # Flip last byte

    print("[Test] Sent tampered data, expecting verification failure.")
