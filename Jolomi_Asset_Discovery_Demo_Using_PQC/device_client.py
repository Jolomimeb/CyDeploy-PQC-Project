# device_client.py - Passive responder, sends signed inventory
# This script acts as the IoT device/server. It waits for a connection from the agent,
# performs a key exchange, and sends a signed, encrypted inventory payload.

import socket
from dilithium_utils import generate_keys
from key_exchange_utils import generate_kem_keypair, decapsulate, derive_aes_key
from sign_inventory import prepare_signed_encrypted_inventory

HOST = 'localhost'
PORT = 65432

# Generate Kyber KEM keypair and Dilithium signing keypair
ek, dk = generate_kem_keypair()
dil_pk, dil_sk = generate_keys()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print("[Device] Waiting for discovery agent...")

    conn, addr = s.accept()
    with conn:
        print(f"[Device] Connected by {addr}")
        # Send Kyber public key and Dilithium public key to agent
        conn.sendall(len(ek).to_bytes(2, 'big') + ek + len(dil_pk).to_bytes(2, 'big') + dil_pk)

        # Receive encapsulated key from agent and derive shared AES key
        ct = conn.recv(16384)
        shared_key = decapsulate(dk, ct)
        aes_key = derive_aes_key(shared_key)

        # Wait for trigger from agent (optional)
        trigger = conn.recv(1024)
        # Prepare and send signed, encrypted inventory
        payload = prepare_signed_encrypted_inventory(aes_key, dil_sk)
        conn.sendall(len(payload).to_bytes(4, 'big'))
        conn.sendall(payload)
        print("[Device] Sent signed, encrypted inventory.")
