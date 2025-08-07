import threading
import logging
import socket
import json
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from src.pqc.crypto_handler import PQCHandler, HybridHandler

HOST = '0.0.0.0'
PORT = 65432

logger = logging.getLogger("discovery_server")

# Handles a single client connection
def handle_client(conn, addr, mode, crypto):
    logger.info(f"Connected by {addr} in {mode} mode")
    try:
        if mode == 'pqc':
            # PQC key exchange and inventory receive/verify
            ek, dk, pk, sk = crypto.key_exchange('server')
            print(f"[Server] PQC server keys generated")
            print(f"[Server] ML_KEM_512 public key (bytes): {ek}")
            print(f"[Server] ML_KEM_512 public key (hex): {ek.hex()}")
            print(f"[Server] Dilithium2 public key (bytes): {pk}")
            print(f"[Server] Dilithium2 public key (hex): {pk.hex()}")
            
            # Send Kyber public key and Dilithium public key to client
            conn.sendall(len(ek).to_bytes(2, 'big') + ek + len(pk).to_bytes(2, 'big') + pk)
            logger.info("[Server] Sent ML_KEM_512 and Dilithium2 public keys to client")
            
            # Receive encapsulated key from client and derive shared AES key
            ct = conn.recv(16384)
            shared_key = crypto.decapsulate(dk, ct)
            aes_key = crypto.derive_aes_key(shared_key)
            print(f"[Server] PQC shared_key (bytes): {shared_key}")
            print(f"[Server] PQC shared_key (hex): {shared_key.hex()}")
            print(f"[Server] PQC AES key (bytes): {aes_key}")
            print(f"[Server] PQC AES key (hex): {aes_key.hex()}")
            
            # Wait for trigger from clientt
            trigger = conn.recv(1024)
            logger.info(f"[Server] Received trigger: {trigger.decode()}")
            
            # Receive and verify client inventory info 
            publicKey_info_signature_json = conn.recv(32768).decode('utf-8')
            client_dpk, client_encrypted_info_json, iv, signature = crypto.extract_signed_aes_encrypted_message(publicKey_info_signature_json)
            
            if crypto.verify(client_dpk, client_encrypted_info_json, signature):
                client_inventory = crypto.decrypt_message(aes_key, iv, client_encrypted_info_json)
                logger.info(f"[Server] Client {addr} successful handshake. Inventory received.")
                
                # Save the inventory to a file
                with open(f'inventory_received_{addr[0]}_{addr[1]}.txt', 'w', encoding='utf-8') as f:
                    f.write(client_inventory)
                
                logger.info(f"[Server] Inventory saved to inventory_received_{addr[0]}_{addr[1]}.txt")
                
                # Parse and display inventory summary
                inventory_data = json.loads(client_inventory)
                logger.info(f"[Server] Received {len(inventory_data)} devices in inventory from {addr}")
            else:
                logger.error(f"[Server] Client {addr} unsuccessful handshake. Signature failed verification.")
                
        elif mode == 'hybrid':
            # Hybrid key exchange and inventory receive/verify
            kem_pk, kem_sk, dsa_pk, dsa_sk, x25519_pk, x25519_sk = crypto.key_exchange('server')
            print(f"[Server] Hybrid server keys generated")
            print(f"[Server] ML_KEM_768 public key (bytes): {kem_pk}")
            print(f"[Server] ML_KEM_768 public key (hex): {kem_pk.hex()}")
            print(f"[Server] ML_DSA_65 public key (bytes): {dsa_pk}")
            print(f"[Server] ML_DSA_65 public key (hex): {dsa_pk.hex()}")
            
            # Serialize X25519 public key for display
            serialized_x25519_pk = crypto.x25519_serialize_public_key(x25519_pk)
            print(f"[Server] X25519 public key (bytes): {serialized_x25519_pk}")
            print(f"[Server] X25519 public key (hex): {serialized_x25519_pk.hex()}")
            
            # Receive client's ML_KEM public key
            client_kpk = conn.recv(32768)
            logger.info("[Server] Received client's ML_KEM_768 public key")
            
            # Generate ML_KEM secret and ciphertext
            secret, ciphertext = crypto.encapsulate(client_kpk)
            print(f"[Server] Hybrid ML_KEM_768 secret (bytes): {secret}")
            print(f"[Server] Hybrid ML_KEM_768 secret (hex): {secret.hex()}")
            
            # Send DSA public key, ciphertext, and signature in JSON
            signed_payload = crypto.sign(dsa_sk, dsa_pk, ciphertext)
            # Ensure we send as UTF-8 encoded JSON string
            signed_payload_bytes = signed_payload.encode('utf-8')
            conn.send(signed_payload_bytes)
            logger.info("[Server] Sent signed ML_KEM_768 ciphertext to client")
            
            # Handle X25519 hybrid key exchange
            serialized_client_epk = conn.recv(1024)
            logger.info("[Server] Received client's X25519 public key")
            
            # Derive X25519 secret
            derived_e_secret = crypto.x25519_derive_secret(serialized_client_epk, x25519_sk, 16)
            print(f"[Server] X25519 (Classical) half (bytes): {derived_e_secret}")
            print(f"[Server] X25519 (Classical) half (hex): {derived_e_secret.hex()}")
            
            # Send X25519 public key to client
            conn.send(serialized_x25519_pk)
            logger.info("[Server] Sent X25519 public key to client")
            
            # Combine secrets for hybrid
            hybrid_secret = secret[:16] + derived_e_secret
            print(f"[Server] New Hybrid shared secret key (bytes): {hybrid_secret}")
            print(f"[Server] New Hybrid shared secret key (hex): {hybrid_secret.hex()}")
            
            # Receive and verify client inventory info
            publicKey_info_signature_json = conn.recv(32768).decode('utf-8')
            client_dpk, client_encrypted_info_json, iv, signature = crypto.extract_signed_aes_encrypted_message(publicKey_info_signature_json)
            
            if crypto.verify(client_dpk, client_encrypted_info_json, signature):
                client_inventory = crypto.decrypt_message(hybrid_secret, iv, client_encrypted_info_json)
                logger.info(f"[Server] Client {addr} successful handshake. Inventory received.")
                
                # Save the inventory to a file
                with open(f'inventory_received_{addr[0]}_{addr[1]}.txt', 'w', encoding='utf-8') as f:
                    f.write(client_inventory)
                
                logger.info(f"[Server] Inventory saved to inventory_received_{addr[0]}_{addr[1]}.txt")
                
                # Parse and display inventory summary
                inventory_data = json.loads(client_inventory)
                logger.info(f"[Server] Received {len(inventory_data)} devices in inventory from {addr}")
            else:
                logger.error(f"[Server] Client {addr} unsuccessful handshake. Signature failed verification.")
                
        else:
            logger.error(f"Unknown mode: {mode}")
    except Exception as e:
        logger.error(f"Error handling client {addr}: {e}")
    finally:
        conn.close()
        logger.info(f"Connection with {addr} closed.")

def run_server(mode='pqc'):
    logging.basicConfig(level=logging.INFO)
    crypto = PQCHandler() if mode == 'pqc' else HybridHandler()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        logger.info(f"Server running in {mode} mode on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr, mode, crypto))
            thread.start()