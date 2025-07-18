# pqc_server.py (Target Device using ML_KEM + Dilithium for signature verification)
import socket
import json
import hashlib
from Crypto.Cipher import AES
from kyber_py.ml_kem import ML_KEM_512
from dilithium_py.dilithium import Dilithium2

HOST = '0.0.0.0'
PORT = 65432

# Generate ML-KEM key pair
ek, dk = ML_KEM_512.keygen()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print("[Server] Listening for connection...")

    conn, addr = s.accept()
    with conn:
        print(f"[Server] Connected by {addr}")

        # Receive ML-KEM and Dilithium public keys
        ek_len = int.from_bytes(conn.recv(2), 'big')
        client_ek = conn.recv(ek_len)
        pk_len = int.from_bytes(conn.recv(2), 'big')
        client_dil_pk = conn.recv(pk_len)

        # Generate and send ciphertext for key encapsulation
        key, ct = ML_KEM_512.encaps(client_ek)
        conn.sendall(ct)
        aes_key = hashlib.sha256(key).digest()

        # Receive encrypted and signed request
        data = conn.recv(4096)
        nonce, tag, enc_data = data[:16], data[16:32], data[32:]
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(enc_data, tag)

        # Extract signature and message
        sig_len = int.from_bytes(decrypted[:2], 'big')
        signature = decrypted[2:2+sig_len]
        message = decrypted[2+sig_len:]

        print("[Server] Received signed message:", message.decode())

        if Dilithium2.verify(client_dil_pk, message, signature):
            print("[Server] Signature verified.")
        else:
            print("[Server] Signature invalid. Dropping connection.")
            conn.close()
            exit()


