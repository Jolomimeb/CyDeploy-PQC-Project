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

        #client connects to server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('127.0.0.1', 1026))
        addr = client_socket.getsockname()

        client_socket.recv(32768)     #hangs for server response before sending anything

        #sends 1st message: choice of pure or hybrid pqc
        print(f"Client {addr} connected to localhost server on port 1026. KEM Mode: {kem_choice}. Sending certificate to server...")
        client_socket.send(kem_choice.encode())

        #sends certificate, receives a challenge from server, sends signature of challenge back
        client_socket.send(certificate.encode())
        challenge_message = client_socket.recv(32768)
        if not challenge_message:
            print(f"\nClient {addr} certificate was not verified.")
        else:
            print(f"\nClient {addr} certificate was verified, received challenge from server, and sending its signature...")
        client_socket.send((ML_DSA_Functions.signed_message_payload(dsk, dpk, challenge_message)).encode())

        #client sends its ML-KEM public key with signature
        client_socket.send((ML_DSA_Functions.signed_message_payload(dsk, dpk, kpk)).encode())

        #receive server's public DSA key, ciphertext, and signature
        publicKey_ciphertext_signature_json = client_socket.recv(32768).decode()
        server_dpk, ciphertext, signature = ML_DSA_Functions.extract_signed_message_payload(publicKey_ciphertext_signature_json)

        #Once verified, decapsulates secret and uses it to AES encrypt json system information and send to server
        if ML_DSA_Functions.verify_signature(server_dpk, ciphertext, signature):
            #PQC shared secret created from ciphertext and private ML_KEM key
            print(f"Client {addr} challenge signature was verified. Received ciphertext from server and verified signature. Generating ML_KEM secret...")
            secret = ML_KEM_Functions.decapsulate(ksk, ciphertext)

            #hybrid mode has additional exchange of X25519 public keys
            if kem_choice == "H":
                #client sends its X25519 public key and signs it
                serialized_epk = X25519_Functions.serialize_public_key(epk)
                print(f"Client {addr} sending X25519 public key to server...")
                client_socket.send((ML_DSA_Functions.signed_message_payload(dsk, dpk, serialized_epk)).encode())

                #receives server's X25519 public key and derives 16-byte X25519 secret
                serialized_server_epk = client_socket.recv(1024)
                print(f"Client {addr} received server's X25519 public key. Deriving X25519 secret...\n")
                derived_e_secret = X25519_Functions.derive_secret(serialized_server_epk, esk, 16)

                #splits previous PQC secret in half and concats X25519 secret
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
    except Exception as e:
        print(f"Error: {e}")
    

#multiple clients connecting simultaneously 
while True: 
    try:
        client_num = int(input("Number of concurrent clients connecting to server between 1 and 64 inclusive: "))
        if client_num < 1 or client_num > 64:
            print("Input not in range")
            continue
        for client in range(client_num):
            #half are hybrid and half are pure
            if client%2 == 0:
                kem_choice = "P"
            else:
                kem_choice = "H"
            client_socket_info = {"hostname":"mockdevice_" + str(client), "os":"Windows 11", "ip":"127.0.0.1"}
            threading.Thread(target= client_connect, args= (client_socket_info, kem_choice)).start()
    except Exception as e:
        print("Invalid Input")
        continue
    break
