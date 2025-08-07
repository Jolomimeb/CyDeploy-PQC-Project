import secrets, socket, ML_KEM_Functions, ML_DSA_Functions, X25519_Functions, Certificate_Functions

#handshake with client, then receives their system information
def receiving(conn, addr):
    while True:

        conn.send(b" ")     #client will start sending messages after server sends first response

        #expects kem_choice as first message after client connection
        kem_choice = conn.recv(32768).decode()
        print(f"\nClient {addr} connected. KEM Mode: {kem_choice}")

        #expects client certificate and gets public ML-DSA key
        client_certificate = conn.recv(32768).decode()
        client_dpk = Certificate_Functions.get_public_key(client_certificate)

        if Certificate_Functions.verify_leaf_certificate(client_certificate):
            #sends challenge to client and gets signature. Verification means that client has certificate's associated secret key
            print("Trusted client certificate")
            challenge_message = iv = secrets.token_bytes(32)
            conn.send(challenge_message)
            signed_message_payload_json = conn.recv(32768).decode()
            client_challenge_signature = ML_DSA_Functions.extract_signed_message_payload(signed_message_payload_json)[2]
            if ML_DSA_Functions.verify_signature(client_dpk, challenge_message, client_challenge_signature):
                print("Challenge signature verified")
            else:
                print("Challenge signature failed")
                conn.close()
                break
        else:
            print("Not trusted client certificate")
            print(len(client_certificate))
            print(client_certificate)
            conn.close()
            break

            
        #expects ML-KEM publicKey and signature after certificate verified and challenge solved
        signed_message_payload_json = conn.recv(32768).decode()
        client_kpk, client_kpk_signature = ML_DSA_Functions.extract_signed_message_payload(signed_message_payload_json)[1], ML_DSA_Functions.extract_signed_message_payload(signed_message_payload_json)[2]
        if ML_DSA_Functions.verify_signature(client_dpk, client_kpk, client_kpk_signature):
            print("Client's ML_KEM public key received and signature verified")
        else:
            print("Client's ML_KEM public key signature failed")
            conn.close()
            break

        #creates secret, corresponding ciphertext, and signature of ciphertext. Sends DSA public key, ciphertext, and sig in json format
        secret, ciphertext = ML_KEM_Functions.encapsulate(client_kpk)
        conn.send((ML_DSA_Functions.signed_message_payload(dsk, dpk, ciphertext)).encode())
        print("Generating ML_KEM secret and sending ciphertext to client...")

        if kem_choice == "H":
            #expects X25519 publicKey and signature after sending ML_KEM secret ciphertext
            signed_message_payload_json = conn.recv(32768).decode()
            serialized_client_epk, serialized_client_epk_signature = ML_DSA_Functions.extract_signed_message_payload(signed_message_payload_json)[1], ML_DSA_Functions.extract_signed_message_payload(signed_message_payload_json)[2]
            if ML_DSA_Functions.verify_signature(client_dpk, serialized_client_epk, serialized_client_epk_signature):
                print("Client's X25519 public key received and signature verified")
            else:
                print("Client's  X25519 public key signature failed")
                conn.close()
                break

            print("Deriving X25519 secret...")
            derived_e_secret = X25519_Functions.derive_secret(serialized_client_epk, esk, 16)

            serialized_epk = X25519_Functions.serialize_public_key(epk)
            print("Sending X25519 public key to client...")
            conn.send(serialized_epk)

            print("\nML_KEM (PQC) secret half: " + str(secret[:16]))
            print("X25519 (Classical) secret half: " + str(derived_e_secret))
            secret = secret[:16] + derived_e_secret
            print("New Hybrid shared secret key: " + str(secret) +"\n")
        else:
            print("\nML_KEM (PQC) shared secret key: " + str(secret) + "\n")

        #receives DSA public key, system information from client in json format (encrypted with shared secret), iv used for encryption, and signature
        publicKey_info_signature_json = conn.recv(32768).decode()
        client_dpk, client_encrypted_info_json, iv, signature = ML_DSA_Functions.extract_signed_AES_encrypted_message_payload(publicKey_info_signature_json)

        if ML_DSA_Functions.verify_signature(client_dpk, client_encrypted_info_json, signature):
            client_info = ML_DSA_Functions.decrypted_message(secret, iv, client_encrypted_info_json)
            print(f"Client {addr} successful handshake. System info: {client_info}")
        else:  
            print(f"Client {addr} unsuccessful handshake. Signature failed verification.")
            conn.close()
            break

        data = conn.recv(32768)
        if not data:
            print(f"Client {addr} disconnected.\n")
            conn.close()

        break

#handle multiple client connections iterably
def accepting():
    while True:
        conn, addr = server_socket.accept()
        receiving(conn, addr)

#creating server's KEM and DSA key pairs and starting server.
kpk, ksk = ML_KEM_Functions.public_private_keygen()
dpk, dsk = ML_DSA_Functions.public_private_keygen()
#Also creates X25519 key pairs for if client choses Hybrid KEM
epk, esk = X25519_Functions.public_private_keygen()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('127.0.0.1', 1026))
server_socket.listen()
print(f"Server {server_socket.getsockname()} up.\n" )

#start actually receiving connections with the intent of handshake
accepting()

