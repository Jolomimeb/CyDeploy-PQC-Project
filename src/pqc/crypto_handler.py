from abc import ABC, abstractmethod

# PQC imports
from .dilithium2_functions import generate_keys as pqc_generate_keys, sign_message as pqc_sign_message, verify_signature as pqc_verify_signature
from .ml_kem_512_functions import generate_kem_keypair as pqc_generate_kem_keypair, encapsulate as pqc_encapsulate, decapsulate as pqc_decapsulate, derive_aes_key as pqc_derive_aes_key

# Hybrid imports
from .ml_kem_768_functions import public_private_keygen as hybrid_kem_keygen, encapsulate as hybrid_encapsulate, decapsulate as hybrid_decapsulate
from .ml_dsa_65_functions import public_private_keygen as hybrid_dsa_keygen, verify_signature as hybrid_verify_signature, signed_message_payload as hybrid_signed_message_payload, signed_AES_encrypted_message_payload as hybrid_signed_AES_encrypted_message_payload, extract_signed_message_payload as hybrid_extract_signed_message_payload, extract_signed_AES_encrypted_message_payload as hybrid_extract_signed_AES_encrypted_message_payload, decrypted_message as hybrid_decrypted_message
from .x25519_functions import public_private_keygen as x25519_keygen, serialize_public_key as x25519_serialize_public_key, derive_secret as x25519_derive_secret

class CryptoHandler(ABC):
    """Abstract base class for cryptographic operations."""
    @abstractmethod
    def key_exchange(self, *args, **kwargs):
        pass

    @abstractmethod
    def sign(self, *args, **kwargs):
        pass

    @abstractmethod
    def verify(self, *args, **kwargs):
        pass

class PQCHandler(CryptoHandler):
    """Handler for pure PQC operations (ML_KEM_512, Dilithium2)."""
    def key_exchange(self, role, *args, **kwargs):
        if role == 'server':
            # Server generates keypairs
            ek, dk = pqc_generate_kem_keypair()
            pk, sk = pqc_generate_keys()
            return ek, dk, pk, sk
        elif role == 'client':
            # Client generates keypair
            ek, dk = pqc_generate_kem_keypair()
            return ek, dk

    def encapsulate(self, device_ek):
        return pqc_encapsulate(device_ek)

    def decapsulate(self, dk, ct):
        return pqc_decapsulate(dk, ct)

    def derive_aes_key(self, shared_key):
        return pqc_derive_aes_key(shared_key)

    def sign(self, sk, message: bytes) -> bytes:
        return pqc_sign_message(sk, message)

    def verify(self, pk, message: bytes, signature: bytes) -> bool:
        return pqc_verify_signature(pk, message, signature)

    def sign_aes_encrypted(self, secret, private_key, public_key, message: str) -> str:
        """Sign and AES encrypt a message using PQC (Dilithium2 + AES)."""
        # Convert message to bytes
        message_bytes = message.encode('utf-8')
        
        # Import AES encryption functions
        import secrets
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
        import json
        
        # Generate IV for AES encryption
        iv = secrets.token_bytes(16)
        
        # Encrypt the message with AES-CBC
        cipher = Cipher(algorithms.AES(secret), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Pad the message to block size
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message_bytes) + padder.finalize()
        
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
        
        # Sign the encrypted message with Dilithium2
        signature = pqc_sign_message(private_key, encrypted_message)
        
        # Create JSON payload with all components
        payload = {
            "public_key": public_key.hex(),
            "encrypted_message": encrypted_message.hex(),
            "iv": iv.hex(),
            "signature": signature.hex()
        }
        
        return json.dumps(payload)

    def extract_signed_aes_encrypted_message(self, signed_AES_encrypted_message_payload: str):
        """Extract components from signed AES encrypted message payload."""
        import json
        
        # Parse the JSON payload
        payload = json.loads(signed_AES_encrypted_message_payload)
        
        # Extract components
        public_key = bytes.fromhex(payload["public_key"])
        encrypted_message = bytes.fromhex(payload["encrypted_message"])
        iv = bytes.fromhex(payload["iv"])
        signature = bytes.fromhex(payload["signature"])
        
        return public_key, encrypted_message, iv, signature

    def decrypt_message(self, secret, iv, encrypted_message):
        """Decrypt AES encrypted message."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
        
        # Decrypt with AES-CBC
        cipher = Cipher(algorithms.AES(secret), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        decrypted_padded = decryptor.update(encrypted_message) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
        
        return decrypted_data.decode('utf-8')

class HybridHandler(CryptoHandler):
    """Handler for hybrid ML_KEM_768 + ML_DSA_65 + X25519 operations."""
    def key_exchange(self, role, *args, **kwargs):
        if role == 'server':
            kem_pk, kem_sk = hybrid_kem_keygen()
            dsa_pk, dsa_sk = hybrid_dsa_keygen()
            x25519_pk, x25519_sk = x25519_keygen()
            return kem_pk, kem_sk, dsa_pk, dsa_sk, x25519_pk, x25519_sk
        elif role == 'client':
            kem_pk, kem_sk = hybrid_kem_keygen()
            dsa_pk, dsa_sk = hybrid_dsa_keygen()
            x25519_pk, x25519_sk = x25519_keygen()
            return kem_pk, kem_sk, dsa_pk, dsa_sk, x25519_pk, x25519_sk

    def encapsulate(self, public_key):
        return hybrid_encapsulate(public_key)

    def decapsulate(self, private_key, ciphertext):
        return hybrid_decapsulate(private_key, ciphertext)

    def sign(self, private_key, public_key, message: bytes) -> str:
        return hybrid_signed_message_payload(private_key, public_key, message)

    def verify(self, public_key, message: bytes, signature: bytes) -> bool:
        return hybrid_verify_signature(public_key, message, signature)

    def sign_aes_encrypted(self, secret, private_key, public_key, message: str) -> str:
        return hybrid_signed_AES_encrypted_message_payload(secret, private_key, public_key, message)

    def extract_signed_message(self, signed_message_payload: str):
        return hybrid_extract_signed_message_payload(signed_message_payload)

    def extract_signed_aes_encrypted_message(self, signed_AES_encrypted_message_payload: str):
        return hybrid_extract_signed_AES_encrypted_message_payload(signed_AES_encrypted_message_payload)

    def decrypt_message(self, secret, iv, encrypted_message):
        return hybrid_decrypted_message(secret, iv, encrypted_message)

    def x25519_serialize_public_key(self, public_key):
        return x25519_serialize_public_key(public_key)

    def x25519_derive_secret(self, received_serialized_public_key, your_private_key, key_length_bytes):
        return x25519_derive_secret(received_serialized_public_key, your_private_key, key_length_bytes)