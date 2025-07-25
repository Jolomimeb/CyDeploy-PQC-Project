from kyber_py.ml_kem import ML_KEM_768

def public_private_keygen():
    return ML_KEM_768.keygen()

#returns tuplet of secret, and corresponding ciphertext. Ciphertext can return secret when decapsulated with corresponding private key
def encapsulate(public_key):
    return ML_KEM_768.encaps(public_key)

#returns secret with ciphertext's corresponding private key
def decapsulate(private_key, ciphertext):
    return ML_KEM_768.decaps(private_key, ciphertext)