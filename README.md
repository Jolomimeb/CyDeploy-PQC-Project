# PQC Discovery With Certificates

## Running the Program

  1. Run Create_Root_Intermediate_Certificates.py to create and write (or replace) to the directory the Root certificate, Intermediate certificate, and Intermediate private key
  2. Run Discovery_Server.py to start server and listen for TCP connections
  3. Run Discovery_Client.py to have clients start connecting to server

  Certificate_Functions.py, ML_DSA_Functions.py, ML_KEM_Functions.py, and X25519_Functions.py are called by the client and server files
  
## Program Description

          The program simulates a mock TLS handshake between multiple client discovery agents and a server with each 
     client sending their system information once finished. The handshake consists of the client selecting the mode 
     (pure PQC or hybrid PQC), sending the its certificate that contains their ML-DSA public key for singing, each 
     party sending the appropriate public keys (ML-KEM or ML-KEM & classical X25519) to each other depending on the 
     mode and deriving a shared secret, and using that shared secret for the client to encrypt and server to decrypt 
     the system information. 
     
          The program also simulates a simple representation of an X.509 Certificate Authority that allows the server 
     to verify that the public ML-DSA key of the certificate the client sends is trusted. The server then verifies 
     that the public key actually belongs to the client by sending a challenge and getting a signature back to verify. 
     With the signing key being trusted, it is used to sign the rest of they ML-KEM and X25519 key exchanges to ensure 
     they were truly send by the client as well. The goal of this program was to demo how a TLS connection with certificates 
     would function for either a custom discovery call or when Certifiate Authorities begin to issue PQC certificates.

## Detailed Steps

  1. Server creates TCP socket on localhost port 1026 and listens for connections
  2. Multiple (5 in this program) clients connect simultaneously to server on localhost port 1026
  3. Server accepts client connections iterably, sending a response string to signal the client to start handshake process
  4. Client sends pure/hybrid PQC choice "P" or "H"
  5. Client sends its certificate which was issued by the intermediate CA and that issued by the Root CA
  6. Server verifies that the client's certificate was issued up the CA chain and sends a random challenge to the client
  7. Client creates a signature of the challenge and sends it to the server along with its ML-KEM public key, also signed
  8. Server verifies the challenge signature and ML-KEM public key signature before using client's public key to deriving PQC secret and sending its ciphertext back, signed
  9. Client verifies received ciphertext signature and uses its own private key to derive the same PQC secret
  10. (If mode is hybrid PQC) Client sends its X25519 public key to server with signature, server verifies it and sends its own X25519 public key back. The classical secret is then derived on both ends using the received public keys and their own private keys. The PQC secret is cut in half and the classical secret is concatenated to form the new shared secret
  11. The secret is used by the client to AES256 encrypt its mock system information and send to server
  12. The server uses the secret to decrypt the received information

## Python Modules Used

-dilithium_py: ML_DSA_65 parameter set and functions  
-kyber_py: ML_KEM_768 parameter set and functions  
-cryptography: X25519 functions, AES encryption  
-socket: TCP communication  
-secrets: cryptographically secure pseudorandom numbers  
-threading: multiple concurrent client connections  
-json: formatting and extracting data sent  
-filelock: handing functions that read files  
