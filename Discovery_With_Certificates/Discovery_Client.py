import socket, threading, json, ML_KEM_Functions, ML_DSA_Functions, X25519_Functions, Certificate_Functions

#represents a client connecting to the server socket and initiating handshake
def client_connect(client_socket_info, kem_choice):
    try:
        #client creates key pairs for both ML_KEM and ML_DSA
        kpk, ksk = ML_KEM_Functions.public_private_keygen()
        dpk, dsk = ML_DSA_Functions.public_private_keygen()
        #Also creates X25519 key pairs for if Hybrid KEM is chosen
        epk, esk = X25519_Functions.public_private_keygen()

        #simulates being issued a certificate by the intermediate CA with the public key being ML-DSA
        certificate = Certificate_Functions.issue_leaf_certificate(client_socket_info["hostname"], dpk)

        #client connects to server and sends 1st message: choice of pure or hybrid pqc
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #print("Connecting to localhost server on port 1026...")
        client_socket.connect(('127.0.0.1', 1026))
        addr = client_socket.getsockname()

        client_socket.recv(32768)     #hangs for server response

        client_socket.send(kem_choice.encode())
        
        print(f"Client {addr} connected to localhost server on port 1026. KEM Mode: {kem_choice}. Sending certificate to server...")

        #sends certificate, receives a challenge from server, sends signature of challenge back
        client_socket.send(certificate.encode())
        challenge_message = client_socket.recv(32768)
        client_socket.send((ML_DSA_Functions.signed_message_payload(dsk, dpk, challenge_message)).encode())

        #client sends its ML-KEM public key and signs it
        client_socket.send((ML_DSA_Functions.signed_message_payload(dsk, dpk, kpk)).encode())

        #receive server's public DSA key, ciphertext, and signature
        publicKey_ciphertext_signature_json = client_socket.recv(32768).decode()
        server_dpk, ciphertext, signature = ML_DSA_Functions.extract_signed_message_payload(publicKey_ciphertext_signature_json)

        if ML_DSA_Functions.verify_signature(server_dpk, ciphertext, signature):
            #Once verified, use secret to AES encrypt json system information and send to server
            print(f"\nClient {addr} received ciphertext from server and verified signature. Generating ML_KEM secret...")
            secret = ML_KEM_Functions.decapsulate(ksk, ciphertext)

            if kem_choice == "H":
                #client sends its X25519 public key and signs it
                serialized_epk = X25519_Functions.serialize_public_key(epk)
                print(f"Client {addr} sending X25519 public key to server...")
                client_socket.send((ML_DSA_Functions.signed_message_payload(dsk, dpk, serialized_epk)).encode())

                serialized_server_epk = client_socket.recv(1024)
                print(f"Client {addr} received server's X25519 public key. Deriving X25519 secret...\n")
                derived_e_secret = X25519_Functions.derive_secret(serialized_server_epk, esk, 16)

                print("ML_KEM (PQC) secret half: " + str(secret[:16]))
                print("X25519 (Classical) secret half: " + str(derived_e_secret))
                secret = secret[:16] + derived_e_secret
                print("New Hybrid shared secret key: " + str(secret))
            else:
                print("\nML_KEM (PQC) shared secret key: " + str(secret))
            
            client_socket_info_json = json.dumps(client_socket_info)
            print(f"\nClient {addr} Encrypting with shared secret and sending system info: {client_socket_info_json}")
            publicKey_info_iv_signature_json = ML_DSA_Functions.signed_AES_encrypted_message_payload(secret, dsk, dpk, client_socket_info_json)

            client_socket.send(publicKey_info_iv_signature_json.encode())
            client_socket.close()
            print(f"Client {addr} disconnected.\n\n")
        else:
            print(f"Client {addr} disconnected. Server signature failed verification.\n\n")
            client_socket.close()
    except ConnectionAbortedError:
        print(f"Client {addr} disconnected. Failed handshake with server.\n\n")
              
    except ConnectionRefusedError:
        print("Client connection failed. localhost server on port 1026 is not reachable.")
    
    
#multiple clients connecting simultaneously
client1_socket_info = {"hostname":"mockdevice_1", "os":"Windows 11", "ip":"127.0.0.1"}
client2_socket_info = {"hostname":"mockdevice_2", "os":"Windows 11", "ip":"127.0.0.1"}
client3_socket_info = {"hostname":"mockdevice_3", "os":"Windows 11", "ip":"127.0.0.1"}
client4_socket_info = {"hostname":"mockdevice_4", "os":"Windows 11", "ip":"127.0.0.1"}
client5_socket_info = {"hostname":"mockdevice_5", "os":"Windows 11", "ip":"127.0.0.1"}

thread1 = threading.Thread(target=client_connect, args=(client1_socket_info, "P"))
thread2 = threading.Thread(target=client_connect, args=(client2_socket_info, "H"))
thread3 = threading.Thread(target=client_connect, args=(client3_socket_info, "P"))
thread4 = threading.Thread(target=client_connect, args=(client4_socket_info, "H"))
thread5 = threading.Thread(target=client_connect, args=(client5_socket_info, "P"))

thread1.start()
thread2.start()
thread3.start()
thread4.start()
thread5.start()
