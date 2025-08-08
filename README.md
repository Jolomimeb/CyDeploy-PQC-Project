# PQC Discovery With Certificates

## Running the Program
  1. Run Create_Root_Intermediate_Certificates.py to create and write to the directory the Root certificate, Intermediate certificate, and Intermediate private key
  2. Run Discovery_Server.py to start server and listen for connections
  3. Run Discovery_Client.py to have clients start connecting to server

## Program Description
  The program simulates a mock TLS handshake between multiple client discovery agents and a server with each client sending their system information once finished. The handshake consists of the client selecting the mode (pure PQC or hybrid PQC), each party sending the appropriate public keys to each other depending on the mode and deriving a shared secret, and using that shared secret for the client to encrypt and server to decrypt the system information.
