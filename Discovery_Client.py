import socket, threading, json, ML_KEM_Functions, ML_DSA_Functions, X25519_Functions, Certificate_Functions

def client_connect(client_socket_info):
    #client creates key pairs for both ML_KEM and ML_DSA
    kpk, ksk = ML_KEM_Functions.public_private_keygen()
    dpk, dsk = ML_DSA_Functions.public_private_keygen()
    #Also creates X25519 key pairs for if Hybrid KEM is chosen
    epk, esk = X25519_Functions.public_private_keygen()

    #simulates being issued a certificate by the intermediate CA with the public key being ML-DSA
    certificate = Certificate_Functions.issue_leaf_certificate(client_socket_info["hostname"], dpk)

    #client connects to server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 1026))
    addr = client_socket.getsockname()
    print(f"Client {addr} connected. Sending certificate to server...")

    #clients sends certificate to server
    client_socket.send(certificate.encode())
    challenge_message = client_socket.recv(32768)
    client_socket.send((ML_DSA_Functions.signed_message_payload(dsk, dpk, challenge_message)).encode())

    #client sends its public key 
    client_socket.send(kpk)

    #receive server's public DSA key, ciphertext, and signature
    publicKey_ciphertext_signature_json = client_socket.recv(32768).decode()
    server_dpk, ciphertext, signature = ML_DSA_Functions.extract_signed_message_payload(publicKey_ciphertext_signature_json)

    if ML_DSA_Functions.verify_signature(server_dpk, ciphertext, signature):
        #Once verified, use secret to AES encrypt json system information and send to server
        print(f"\nClient {addr} received ciphertext from server and verified signature. Generating ML_KEM secret...")
        secret = ML_KEM_Functions.decapsulate(ksk, ciphertext)

        if kem_choice == "H":
            serialized_epk = X25519_Functions.serialize_public_key(epk)
            print(f"Client {addr} sending X25519 public key to server...")
            client_socket.send(serialized_epk)

            serialized_server_epk = client_socket.recv(1024)
            print(f"Client {addr} received server's X25519 public key. Deriving X25519 secret...\n")
            derived_e_secret = X25519_Functions.derive_secret(serialized_server_epk, esk, 16)

            print("ML_KEM (PQC) half: " + str(secret[:16]))
            print("X25519 (Classical) half: " + str(derived_e_secret))
            secret = secret[:16] + derived_e_secret
            print("New Hybrid shared secret key: " + str(secret))
        else:
            print("\nML_KEM (PQC) shared secret key: " + str(secret))
        
        client_socket_info_json = json.dumps(client_socket_info)
        print(f"\nClient {addr} Encrypting with shared secret and sending system info: {client_socket_info_json}")
        publicKey_info_iv_signature_json = ML_DSA_Functions.signed_AES_encrypted_message_payload(secret, dsk, dpk, client_socket_info_json)
        client_socket.send(publicKey_info_iv_signature_json.encode())
        client_socket.close()
        print(f"Client {addr} disconnected.\n")
    else:
        print(f"Client {addr} disconnected. Server signature failed verification.\n")
        client_socket.close()

print("Connecting to localhost server on port 1026...")

#multiple clients connecting simultaneously
try:
    while True:
        kem_choice = input("Enter (P) for pure PQC key exchange or (H) for hybrid key exhange: ").upper()
        if kem_choice != "P" and kem_choice != "H":
            print("Invalid Input\n")
            continue
        break
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 1026))
    client_socket.send(kem_choice.encode())
    client_socket.close()
    
    client1_socket_info = {"hostname":"mockdevice_1", "os":"Windows 11", "ip":"127.0.0.1"}
    client2_socket_info = {"hostname":"mockdevice_2", "os":"Windows 10", "ip":"127.0.0.1"}
    client3_socket_info = {"hostname":"mockdevice_3", "os":"Windows 11", "ip":"127.0.0.1"}
    client4_socket_info = {"hostname":"mockdevice_4", "os":"Windows 10", "ip":"127.0.0.1"}
    client5_socket_info = {"hostname":"mockdevice_5", "os":"Windows 11", "ip":"127.0.0.1"}
    
    thread1 = threading.Thread(target=client_connect, args=(client1_socket_info,))
    thread2 = threading.Thread(target=client_connect, args=(client2_socket_info,))
    thread3 = threading.Thread(target=client_connect, args=(client3_socket_info,))
    thread4 = threading.Thread(target=client_connect, args=(client4_socket_info,))
    thread5 = threading.Thread(target=client_connect, args=(client5_socket_info,))

    thread1.start()
    thread2.start()
    thread3.start()
    thread4.start()
    thread5.start()

except ConnectionRefusedError:
    print("Connection failed. localhost server on 1026 is not reachable.")
