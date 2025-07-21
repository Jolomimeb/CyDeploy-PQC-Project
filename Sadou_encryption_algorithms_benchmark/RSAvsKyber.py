import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import oqs  # This now works after you installed liboqs-python

# ---------------------------------------
# 🔐 Classical RSA Key Exchange
# ---------------------------------------
print("--- Classical RSA Key Exchange ---")

# 1. RSA Key Generation (Alice)
start_time = time.time()
rsa_key = RSA.generate(2048)
rsa_public_key = rsa_key.publickey().export_key()
rsa_private_key = rsa_key.export_key()
keygen_time = time.time() - start_time

print(f"RSA Key Generation Time: {keygen_time:.4f} seconds")
print(f"RSA Public Key Size: {len(rsa_public_key)} bytes")
print(f"RSA Private Key Size: {len(rsa_private_key)} bytes")

# 2. RSA Key Encryption (Bob encrypts a shared secret)
dummy_secret_key = b"This is a secret key for RSA"

rsa_encryptor = PKCS1_OAEP.new(RSA.import_key(rsa_public_key))
start_time = time.time()
rsa_ciphertext = rsa_encryptor.encrypt(dummy_secret_key)
encryption_time = time.time() - start_time

print(f"RSA Encryption Time: {encryption_time:.4f} seconds")
print(f"RSA Ciphertext Size: {len(rsa_ciphertext)} bytes")

# 3. RSA Key Decryption (Alice)
rsa_decryptor = PKCS1_OAEP.new(RSA.import_key(rsa_private_key))
start_time = time.time()
decrypted_secret_key = rsa_decryptor.decrypt(rsa_ciphertext)
decryption_time = time.time() - start_time

print(f"RSA Decryption Time: {decryption_time:.4f} seconds")
print("RSA Key Exchange Match:", dummy_secret_key == decrypted_secret_key)
print()

# ---------------------------------------
# 🛡️ Post-Quantum Kyber768 Key Exchange
# ---------------------------------------
print("--- Post-Quantum Kyber768 Key Exchange ---")

# 1. Kyber Key Generation (Alice)
with oqs.KeyEncapsulation('Kyber768') as alice:
    start_time = time.time()
    kyber_public_key = alice.generate_keypair()
    keygen_time = time.time() - start_time

    print(f"Kyber Key Generation Time: {keygen_time:.4f} seconds")
    print(f"Kyber Public Key Size: {len(kyber_public_key)} bytes")
    print(f"Kyber Secret Key Size: {len(alice.export_secret_key())} bytes")

    # 2. Kyber Key Encapsulation (Bob)
    with oqs.KeyEncapsulation('Kyber768') as bob:
        start_time = time.time()
        kyber_ciphertext, bob_shared_secret = bob.encap_secret(kyber_public_key)
        encaps_time = time.time() - start_time

        print(f"Kyber Encapsulation Time: {encaps_time:.4f} seconds")
        print(f"Kyber Ciphertext Size: {len(kyber_ciphertext)} bytes")

    # 3. Kyber Key Decapsulation (Alice)
    start_time = time.time()
    alice_shared_secret = alice.decap_secret(kyber_ciphertext)
    decaps_time = time.time() - start_time

    print(f"Kyber Decapsulation Time: {decaps_time:.4f} seconds")
    print("Kyber Key Exchange Match:", bob_shared_secret == alice_shared_secret)
