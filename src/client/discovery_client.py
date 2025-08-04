import logging
import socket
import threading
import json
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from src.pqc.crypto_handler import PQCHandler, HybridHandler
from src.utils.inventory_utils import get_mock_inventory

HOST = '127.0.0.1'
PORT = 65432
logger = logging.getLogger("discovery_client")

def run_client(mode='pqc', simulate_multiple=False):
    """Entry point for running the client. If simulate_multiple is True, spawns multiple clients (hybrid demo style)."""
    logging.basicConfig(level=logging.INFO)
    if simulate_multiple:
        # Simulate multiple clients
        for i in range(5):
            thread = threading.Thread(target=client_logic, args=(mode, f"mockdevice_{i+1}",))
            thread.start()
    else:
        client_logic(mode, "mockdevice_1")

def client_logic(mode, hostname):
    crypto = PQCHandler() if mode == 'pqc' else HybridHandler()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            logger.info(f"[{hostname}] Connected to server in {mode} mode at {HOST}:{PORT}")
            
            if mode == 'pqc':
                # PQC key exchange and inventory send/verify
                ek, dk = crypto.key_exchange('client')
                # Also generate Dilithium2 keys for signing
                pk, sk = crypto.generate_dilithium_keys()
                print(f"[{hostname}] PQC client keys generated")
                print(f"[{hostname}] ML_KEM_512 public key (bytes): {ek}")
                print(f"[{hostname}] ML_KEM_512 public key (hex): {ek.hex()}")
                
                # Receive server's Kyber and Dilithium public keys
                ek_len = int.from_bytes(s.recv(2), 'big')
                server_ek = s.recv(ek_len)
                pk_len = int.from_bytes(s.recv(2), 'big')
                server_pk = s.recv(pk_len)
                print(f"[{hostname}] Received server's ML_KEM_512 public key (bytes): {server_ek}")
                print(f"[{hostname}] Received server's ML_KEM_512 public key (hex): {server_ek.hex()}")
                print(f"[{hostname}] Received server's Dilithium2 public key (bytes): {server_pk}")
                print(f"[{hostname}] Received server's Dilithium2 public key (hex): {server_pk.hex()}")
                
                # Encapsulate and send shared secret
                shared_key, ct = crypto.encapsulate(server_ek)
                aes_key = crypto.derive_aes_key(shared_key)
                print(f"[{hostname}] PQC shared_key (bytes): {shared_key}")
                print(f"[{hostname}] PQC shared_key (hex): {shared_key.hex()}")
                print(f"[{hostname}] PQC AES key (bytes): {aes_key}")
                print(f"[{hostname}] PQC AES key (hex): {aes_key.hex()}")
                
                s.sendall(ct)
                logger.info(f"[{hostname}] Sent encapsulated key to server")
                
                # Send trigger to server
                s.sendall(b'discover')
                logger.info(f"[{hostname}] Sent discovery trigger to server")
                
                # Send inventory data to server using the same approach as hybrid
                inventory_data = get_mock_inventory()
                inventory_json = json.dumps(inventory_data)
                publicKey_info_iv_signature_json = crypto.sign_aes_encrypted(aes_key, sk, pk, inventory_json)
                print("here")
                s.send(publicKey_info_iv_signature_json.encode())
                logger.info(f"[{hostname}] Sent encrypted inventory data to server")
                
                logger.info(f"[{hostname}] Sent {len(inventory_data)} devices in inventory")
                
            elif mode == 'hybrid':
                # Hybrid key exchange and inventory send/verify
                kem_pk, kem_sk, dsa_pk, dsa_sk, x25519_pk, x25519_sk = crypto.key_exchange('client')
                print(f"[{hostname}] Hybrid client keys generated")
                print(f"[{hostname}] ML_KEM_768 public key (bytes): {kem_pk}")
                print(f"[{hostname}] ML_KEM_768 public key (hex): {kem_pk.hex()}")
                print(f"[{hostname}] ML_DSA_65 public key (bytes): {dsa_pk}")
                print(f"[{hostname}] ML_DSA_65 public key (hex): {dsa_pk.hex()}")
                
                # Serialize X25519 public key for display
                serialized_x25519_pk = crypto.x25519_serialize_public_key(x25519_pk)
                print(f"[{hostname}] X25519 public key (bytes): {serialized_x25519_pk}")
                print(f"[{hostname}] X25519 public key (hex): {serialized_x25519_pk.hex()}")
                
                # Send ML_KEM public key
                s.send(kem_pk)
                logger.info(f"[{hostname}] Sent ML_KEM_768 public key to server")
                
                # Receive server's DSA public key, ciphertext, and signature
                signed_payload = s.recv(32768)
                # Try to decode as UTF-8, if it fails, handle as binary
                try:
                    signed_payload_str = signed_payload.decode('utf-8')
                except UnicodeDecodeError:
                    # Handle as binary data - this might be a different format
                    logger.info(f"[{hostname}] Received binary signed payload, length: {len(signed_payload)}")
                    # For now, let's assume it's a JSON string that might have some binary parts
                    # We'll need to handle this more carefully
                    signed_payload_str = signed_payload.decode('utf-8', errors='ignore')
                
                server_dpk, ciphertext, signature = crypto.extract_signed_message(signed_payload_str)
                logger.info(f"[{hostname}] Received server's signed ML_KEM_768 ciphertext")
                
                if crypto.verify(server_dpk, ciphertext, signature):
                    # Decapsulate ML_KEM secret
                    secret = crypto.decapsulate(kem_sk, ciphertext)
                    print(f"[{hostname}] Hybrid ML_KEM_768 secret (bytes): {secret}")
                    print(f"[{hostname}] Hybrid ML_KEM_768 secret (hex): {secret.hex()}")
                    
                    # Send X25519 public key
                    s.send(serialized_x25519_pk)
                    logger.info(f"[{hostname}] Sent X25519 public key to server")
                    
                    # Receive server's X25519 public key
                    serialized_server_epk = s.recv(1024)
                    logger.info(f"[{hostname}] Received server's X25519 public key")
                    
                    # Derive X25519 secret
                    derived_e_secret = crypto.x25519_derive_secret(serialized_server_epk, x25519_sk, 16)
                    print(f"[{hostname}] X25519 (Classical) half (bytes): {derived_e_secret}")
                    print(f"[{hostname}] X25519 (Classical) half (hex): {derived_e_secret.hex()}")
                    
                    # Combine secrets for hybrid
                    hybrid_secret = secret[:16] + derived_e_secret
                    print(f"[{hostname}] New Hybrid shared secret key (bytes): {hybrid_secret}")
                    print(f"[{hostname}] New Hybrid shared secret key (hex): {hybrid_secret.hex()}")
                    
                    # Send inventory data to server using the same function as PQC
                    inventory_data = get_mock_inventory()
                    inventory_json = json.dumps(inventory_data)
                    publicKey_info_iv_signature_json = crypto.sign_aes_encrypted(hybrid_secret, dsa_sk, dsa_pk, inventory_json)
                    s.send(publicKey_info_iv_signature_json.encode())
                    logger.info(f"[{hostname}] Sent encrypted inventory data to server")
                    
                    logger.info(f"[{hostname}] Sent {len(inventory_data)} devices in inventory")
                    
                else:
                    logger.error(f"[{hostname}] Server signature failed verification.")
                    
            else:
                logger.error(f"Unknown mode: {mode}")
    except Exception as e:
        logger.error(f"[{hostname}] Error: {e}")