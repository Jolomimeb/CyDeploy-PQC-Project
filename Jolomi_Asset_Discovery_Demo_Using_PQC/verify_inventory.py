import hashlib
from Crypto.Cipher import AES
from dilithium_utils import verify_signature

def decrypt_and_verify(payload: bytes, shared_key: bytes, dil_pk):
    # Decrypts payload and verifies Dilithium signature

    # Split the payload into nonce, tag, and ciphertext
    nonce, tag, enc_data = payload[:16], payload[16:32], payload[32:]
    cipher = AES.new(shared_key, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(enc_data, tag)

    # Extract signature and inventory
    sig_len = int.from_bytes(decrypted[:2], 'big')
    signature = decrypted[2:2 + sig_len]
    message = decrypted[2 + sig_len:]

    # Verify the signature
    valid = verify_signature(dil_pk, message, signature)
    return message.decode(), valid
