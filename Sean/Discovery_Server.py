import socket
import threading 
import json
from kyber_py.ml_kem import ML_KEM_768
from dilithium_py.ml_dsa import ML_DSA_65
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


#handshake with client, then receives their system information
def receiving(conn, addr):
    while True:
        connected = True
        #expects publicKey as first message after client connection
        client_kpk = conn.recv(32768)
        if not client_kpk:
            print(f"Client {addr} disconnected.\n")
            conn.close()
            break

        #creates secret, corresponding ciphertext, and signature of ciphertext. Sends DSA public key, ciphertext, and sig in json format
        secret, ciphertext = ML_KEM_768.encaps(client_kpk)
        ciphertext_signature = ML_DSA_65.sign(dsk, ciphertext)
        publicKey_ciphertext_signature = {
            "dsa_public_key" : dpk.hex(),
            "ciphertext" : ciphertext.hex(),
            "signature" : ciphertext_signature.hex()
        }
        publicKey_ciphertext_signature_json = json.dumps(publicKey_ciphertext_signature)
        conn.send(publicKey_ciphertext_signature_json.encode())
        
        #receives DSA public key, system information from client in json format (encrypted with shared secret), iv used for encryption, and signature
        publicKey_info_signature_json = conn.recv(32768).decode()
        if not publicKey_info_signature_json:
            print(f"Client {addr} disconnected.\n")
            conn.close()
            break
        publicKey_info_signature = json.loads(publicKey_info_signature_json)

        client_dpk = bytes.fromhex(publicKey_info_signature["dsa_public_key"])
        client_encrypted_info_json = bytes.fromhex(publicKey_info_signature["encrypted_info_json"])
        iv = bytes.fromhex(publicKey_info_signature["iv"])
        signature = bytes.fromhex(publicKey_info_signature["signature"])

        if ML_DSA_65.verify(client_dpk, client_encrypted_info_json, signature):
            cipher = Cipher(algorithms.AES(secret), modes.CBC(iv))
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(128).unpadder()
            client_encrypted_info_decrypted = decryptor.update(client_encrypted_info_json) + decryptor.finalize()
            client_encrypted_info = unpadder.update(client_encrypted_info_decrypted) + unpadder.finalize()
            print(f"Client {addr} successful handshake. System info: {client_encrypted_info.decode()}")
        else:  
            print(f"Client {addr} unsuccessful handshake. Signature failed verification.")

        while connected:
            data = conn.recv(32768)
            if not data:
                print(f"Client {addr} disconnected.\n")
                conn.close()
                connected = False
                continue
            print (f"Client {addr}: {data}")
        break

#handle multiple client connections iterably
def accepting():
    while True:
        conn, addr = server_socket.accept()
        print(f"\nClient {addr} connected.")
        receiving(conn, addr)

#creating server's KEM and DSA key pairs and starting server
kpk, ksk = ML_KEM_768.keygen()
dpk, dsk = ML_DSA_65.keygen()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('127.0.0.1', 1026))
server_socket.listen()
print(f"Server {server_socket.getsockname()} up." )

#accepts first connection from client file (just used by client to see the server is up)
conn, addr = server_socket.accept()
conn.close()

#start actually receiving connections with the intent of handshake
accepting()

