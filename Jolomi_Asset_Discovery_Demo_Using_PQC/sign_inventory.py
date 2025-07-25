import json
import hashlib
from Crypto.Cipher import AES
from dilithium_utils import sign_message
from key_exchange_utils import generate_kem_keypair, derive_aes_key
from inventory_utils import get_mock_inventory

def prepare_signed_encrypted_inventory(shared_key: bytes, dil_sk) -> bytes:
    # Signs + encrypts inventory for secure sending
    # Serialize inventory and sign it
    inventory = json.dumps(get_mock_inventory()).encode()
    signature = sign_message(dil_sk, inventory)
    payload = len(signature).to_bytes(2, 'big') + signature + inventory

    # Encrypt the signed payload with AES-GCM
    cipher = AES.new(shared_key, AES.MODE_GCM)  # default nonce is 16 bytes in this environment
    ciphertext, tag = cipher.encrypt_and_digest(payload)
    return cipher.nonce + tag + ciphertext
