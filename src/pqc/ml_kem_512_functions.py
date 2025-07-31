from kyber_py.ml_kem import ML_KEM_512
import hashlib

def generate_kem_keypair():
    """Generate ML_KEM_512 public/private keypair."""
    return ML_KEM_512.keygen()

def encapsulate(pk: bytes):
    """Encapsulate a shared secret to a public key using ML_KEM_512."""
    return ML_KEM_512.encaps(pk)

def decapsulate(sk: bytes, ct: bytes):
    """Decapsulate a shared secret from a ciphertext using ML_KEM_512."""
    return ML_KEM_512.decaps(sk, ct)

def derive_aes_key(shared_key: bytes):
    """Derive a 256-bit AES key from the shared secret using SHA-256."""
    return hashlib.sha256(shared_key).digest()