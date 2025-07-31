from kyber_py.ml_kem import ML_KEM_768

def public_private_keygen():
    """Generate ML_KEM_768 public/private keypair."""
    return ML_KEM_768.keygen()

def encapsulate(public_key):
    """Encapsulate a shared secret to a public key using ML_KEM_768."""
    return ML_KEM_768.encaps(public_key)

def decapsulate(private_key, ciphertext):
    """Decapsulate a shared secret from a ciphertext using ML_KEM_768."""
    return ML_KEM_768.decaps(private_key, ciphertext)