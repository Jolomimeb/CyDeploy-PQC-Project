# used to establish connection with server, called in the discovery agent
import socket
import json
import hashlib
from Crypto.Cipher import AES
from kyber_py.ml_kem import ML_KEM_512
from dilithium_py.dilithium import Dilithium2

HOST = '192.168.114.130'
PORT = 65432

# Generate ML-KEM key pair and Dilithium key pair
ek, dk = ML_KEM_512.keygen()
dil_pk, dil_sk = Dilithium2.keygen()

def establish_secure_connection():
    # Connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("[Client] Connected to server.")

        # Send ML-KEM public key and Dilithium public key
        s.sendall(len(ek).to_bytes(2, 'big') + ek + len(dil_pk).to_bytes(2, 'big') + dil_pk)
        print("[Client] Sent public keys to server.")

        # Receive ciphertext from server and derive shared key
        ct = s.recv(16384)
        key = ML_KEM_512.decaps(dk, ct)
        aes_key = hashlib.sha256(key).digest()
        print("[Client] Shared key established.")

        # Encrypt a mock discovery request and sign it
        request = json.dumps({"action": "get_inventory"}).encode()
        signature = Dilithium2.sign(dil_sk, request)

        payload = len(signature).to_bytes(2, 'big') + signature + request

        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        s.sendall(cipher.nonce + tag + ciphertext)
        print("[Client] Encrypted signed request sent.")

