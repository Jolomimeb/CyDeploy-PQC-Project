import socket
import threading 
import json
import secrets
from kyber_py.ml_kem import ML_KEM_768
from dilithium_py.ml_dsa import ML_DSA_65
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def client_connect(client_socket_info_json):
    #client creates key pairs for both ML_KEM and ML_DSA
    kpk, ksk = ML_KEM_768.keygen()
    dpk, dsk = ML_DSA_65.keygen()

    #client connects to server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 1026))
    addr = client_socket.getsockname()
    print(f"Client {addr} connected.")
    #client_socket_info_json = json.dumps({"hostname":"mockdevice1", "os":"Windows 11", "ip":"127.0.0.1"})

    #client sends its public key 
    client_socket.send(kpk)

    #receive server's public DSA key, ciphertext, and signature
    publicKey_ciphertext_signature_json = client_socket.recv(32768).decode()
    publicKey_ciphertext_signature = json.loads(publicKey_ciphertext_signature_json)
    server_dpk = bytes.fromhex(publicKey_ciphertext_signature["dsa_public_key"])
    ciphertext = bytes.fromhex(publicKey_ciphertext_signature["ciphertext"])
    signature = bytes.fromhex(publicKey_ciphertext_signature["signature"])

    if ML_DSA_65.verify(server_dpk, ciphertext, signature):
        #Once verified, use secret to AES encrypt json system information and send to server
        secret = ML_KEM_768.decaps(ksk, ciphertext)
        print(f"\nClient {addr} verified signature from server and retrieved secret. Encrypting and sending system info: {client_socket_info_json}")
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(secret), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        client_socket_info_json_padded = padder.update(client_socket_info_json.encode()) + padder.finalize()
        client_socket_info_json_encrypted = encryptor.update(client_socket_info_json_padded) + encryptor.finalize()
        json_signature = ML_DSA_65.sign(dsk, client_socket_info_json_encrypted)
        publicKey_info_signature = {
        "dsa_public_key" : dpk.hex(),
        "encrypted_info_json" : client_socket_info_json_encrypted.hex(),
        "iv" : iv.hex(),
        "signature" : json_signature.hex()
        }
        publicKey_info_signature_json = json.dumps(publicKey_info_signature)
        client_socket.send(publicKey_info_signature_json.encode())
        client_socket.close()
        print(f"Client {addr} disconnected.\n")
    else:
        print(f"Client {addr} disconnected. Server signature failed verification.\n")
        client_socket.close()

print("Connecting to localhost server on port 1026...")

#multiple clients connecting simultaneously
try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 1026))
    client_socket.close()
    
    client1_socket_info_json = json.dumps({"hostname":"mockdevice_1", "os":"Windows 11", "ip":"127.0.0.1"})
    client2_socket_info_json = json.dumps({"hostname":"mockdevice_2", "os":"Windows 10", "ip":"127.0.0.1"})
    client3_socket_info_json = json.dumps({"hostname":"mockdevice_3", "os":"Windows 11", "ip":"127.0.0.1"})
    client4_socket_info_json = json.dumps({"hostname":"mockdevice_4", "os":"Windows 10", "ip":"127.0.0.1"})
    client5_socket_info_json = json.dumps({"hostname":"mockdevice_5", "os":"Windows 11", "ip":"127.0.0.1"})
    
    thread1 = threading.Thread(target=client_connect, args=(client1_socket_info_json,))
    thread2 = threading.Thread(target=client_connect, args=(client2_socket_info_json,))
    thread3 = threading.Thread(target=client_connect, args=(client3_socket_info_json,))
    thread4 = threading.Thread(target=client_connect, args=(client4_socket_info_json,))
    thread5 = threading.Thread(target=client_connect, args=(client5_socket_info_json,))

    thread1.start()
    thread2.start()
    thread3.start()
    thread4.start()
    thread5.start()
except ConnectionRefusedError:
    print("Connection failed. localhost server on 1026 is not reachable.")




