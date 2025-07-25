# discovery_server.py - Active scanner, receives and verifies inventory
# This script acts as the discovery agent (client). It connects to the device,
# performs a key exchange, receives the signed, encrypted inventory, and verifies it.

import socket
from key_exchange_utils import generate_kem_keypair, encapsulate, derive_aes_key
from verify_inventory import decrypt_and_verify

HOST = 'localhost'
PORT = 65432

# Generate our own Kyber KEM keypair (not used for this direction)
ek, dk = generate_kem_keypair()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("[Agent] Connected to device.")

    # Receive device's Kyber public key and Dilithium public key
    ek_len = int.from_bytes(s.recv(2), 'big')
    device_ek = s.recv(ek_len)
    pk_len = int.from_bytes(s.recv(2), 'big')
    dil_pk = s.recv(pk_len)

    # Perform key encapsulation to establish a shared secret
    shared_key, ct = encapsulate(device_ek)
    aes_key = derive_aes_key(shared_key)
    s.sendall(ct)

    # Send trigger to device to request inventory
    s.sendall(b'discover')  
    # Receive the length of the incoming payload
    payload_len_bytes = s.recv(4)
    payload_len = int.from_bytes(payload_len_bytes, 'big')
    # Receive the full payload in chunks
    payload = b''
    while len(payload) < payload_len:
        chunk = s.recv(payload_len - len(payload))
        if not chunk:
            raise RuntimeError('Socket connection broken')
        payload += chunk

    # Decrypt and verify the received inventory
    message, verified = decrypt_and_verify(payload, aes_key, dil_pk)
    # Save the inventory to a file
    with open('inventory_result.txt', 'w', encoding='utf-8') as f:
        f.write(message)
    print("[Agent] Inventory saved to inventory_result.txt")
    print("[Agent] Signature Valid?" , "yes" if verified else "no")
