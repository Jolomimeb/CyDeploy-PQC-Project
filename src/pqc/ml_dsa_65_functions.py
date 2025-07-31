import json, secrets
from dilithium_py.ml_dsa import ML_DSA_65
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def public_private_keygen():
    """Generate ML_DSA_65 public/private keypair."""
    return ML_DSA_65.keygen()

def verify_signature(public_key, message, signature):
    """Verify a signature using ML_DSA_65."""
    return ML_DSA_65.verify(public_key, message, signature)

def signed_message_payload(private_key, public_key, message):
    """Create a JSON payload with public key, message, and signature using ML_DSA_65."""
    signature = ML_DSA_65.sign(private_key, message)
    publicKey_message_signature = {
        "dsa_public_key" : public_key.hex(),
        "message" : message.hex(),
        "signature" : signature.hex()
    }
    return json.dumps(publicKey_message_signature)

def signed_AES_encrypted_message_payload(secret, private_key, public_key, message):
    """AES encrypt message, sign with ML_DSA_65, and return JSON payload."""
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(secret), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    message_padded = padder.update(message.encode()) + padder.finalize()
    message_encrypted = encryptor.update(message_padded) + encryptor.finalize()
    signature = ML_DSA_65.sign(private_key, message_encrypted)
    publicKey_message_iv_signature = {
        "dsa_public_key" : public_key.hex(),
        "encrypted_message" : message_encrypted.hex(),
        "iv" : iv.hex(),
        "signature" : signature.hex()
    }
    return json.dumps(publicKey_message_iv_signature)

def extract_signed_message_payload(signed_message_payload):
    publicKey_message_signature = json.loads(signed_message_payload)
    public_key = bytes.fromhex(publicKey_message_signature["dsa_public_key"])
    message = bytes.fromhex(publicKey_message_signature["message"])
    signature = bytes.fromhex(publicKey_message_signature["signature"])
    return public_key, message, signature

def extract_signed_AES_encrypted_message_payload(signed_AES_encrypted_message_payload):
    publicKey_message_iv_signature = json.loads(signed_AES_encrypted_message_payload)
    public_key = bytes.fromhex(publicKey_message_iv_signature["dsa_public_key"])
    message_encrypted = bytes.fromhex(publicKey_message_iv_signature["encrypted_message"])
    iv = bytes.fromhex(publicKey_message_iv_signature["iv"])
    signature = bytes.fromhex(publicKey_message_iv_signature["signature"])
    return public_key, message_encrypted, iv, signature

def decrypted_message(secret, iv, encrypted_message):
    cipher = Cipher(algorithms.AES(secret), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    message_decrypted = decryptor.update(encrypted_message) + decryptor.finalize()
    message_decrypted_unpadded = unpadder.update(message_decrypted) + unpadder.finalize()
    return message_decrypted_unpadded.decode()