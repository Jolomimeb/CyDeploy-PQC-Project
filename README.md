# CyDeploy-Asset-Discovery-Using-PQC-Project

This project demonstrates the use of Post-Quantum Cryptography (PQC) and Hybrid Cryptography implementation for secure asset discovery.

## Project Overview

Implements a client-server architecture for secure asset discovery using two cryptographic modes:

1. **Pure PQC Mode**: Uses ML-KEM-512 (Kyber) for key exchange and Dilithium2 for digital signatures
2. **Hybrid Mode**: Combines ML-KEM-768 + ML-DSA-65 (quantum-resistant) with X25519 (classical) for enhanced security

## Cryptographic Protocols

### Pure PQC Mode (ML-KEM-512 + Dilithium2)
- **Key Exchange**: ML-KEM-512 (Kyber variant)
- **Digital Signatures**: Dilithium2 (ML-DSA-44 parameters)
- **Encryption**: AES-256-CBC with PKCS7 padding
- **Key Derivation**: SHA-256 for AES key derivation

### Hybrid Mode (ML-KEM-768 + ML-DSA-65 + X25519)
- **Quantum-Resistant**: ML-KEM-768 for key exchange, ML-DSA-65 for signatures
- **Classical**: X25519 for additional key exchange
- **Combined Security**: 32-byte hybrid secret (16 bytes quantum + 16 bytes classical)
- **Encryption**: AES-256-CBC with PKCS7 padding

## Project Structure

### Pure PQC Mode Handshake

1. **Client Key Generation**:
   - Generate ML-KEM-512 keypair (`ek`, `dk`)
   - Generate Dilithium2 keypair (`pk`, `sk`)

2. **Server Key Generation**:
   - Generate ML-KEM-512 keypair (`ek`, `dk`)
   - Generate Dilithium2 keypair (`pk`, `sk`)

3. **Key Exchange**:
   - Server sends ML-KEM-512 and Dilithium2 public keys to client
   - Client encapsulates shared secret using server's ML-KEM-512 public key
   - Client sends encapsulated key to server
   - Server decapsulates shared secret

4. **AES Key Derivation**:
   - Both parties derive AES-256 key using SHA-256(shared_secret)

5. **Inventory Exchange**:
   - Client encrypts inventory with AES-256-CBC
   - Client signs encrypted data with Dilithium2
   - Server verifies signature and decrypts inventory

### Hybrid Mode Handshake

1. **Client Key Generation**:
   - Generate ML-KEM-768 keypair (`kem_pk`, `kem_sk`)
   - Generate ML-DSA-65 keypair (`dsa_pk`, `dsa_sk`)
   - Generate X25519 keypair (`x25519_pk`, `x25519_sk`)

2. **Server Key Generation**:
   - Generate ML-KEM-768 keypair (`kem_pk`, `kem_sk`)
   - Generate ML-DSA-65 keypair (`dsa_pk`, `dsa_sk`)
   - Generate X25519 keypair (`x25519_pk`, `x25519_sk`)

3. **ML-KEM Exchange**:
   - Client sends ML-KEM-768 public key to server
   - Server encapsulates secret using client's public key
   - Server signs ciphertext with ML-DSA-65
   - Server sends signed ciphertext to client
   - Client verifies signature and decapsulates secret

4. **X25519 Exchange**:
   - Client sends X25519 public key to server
   - Server sends X25519 public key to client
   - Both derive X25519 shared secret

5. **Hybrid Secret Combination**:
   - Combine ML-KEM secret (first 16 bytes) + X25519 secret (16 bytes)
   - Result: 32-byte hybrid secret

6. **Inventory Exchange**:
   - Client encrypts inventory with AES-256-CBC using hybrid secret
   - Client signs encrypted data with ML-DSA-65
   - Server verifies signature and decrypts inventory

## How to Run

### Prerequisites
```bash
pip install cryptography dilithium-py kyber-py
```

### Running the Server

**PQC Mode (default):**
```bash
python -m src.main --role server --mode pqc
```

**Hybrid Mode:**
```bash
python -m src.main --role server --mode hybrid
```

### Running the Client

**Single Client (PQC mode):**
```bash
python -m src.main --role client --mode pqc
```

**Single Client (Hybrid mode):**
```bash
python -m src.main --role client --mode hybrid
```

**Multiple Clients (5 concurrent clients):**
```bash
python -m src.main --role client --mode hybrid --simulate-multiple
```

## Command Line Arguments

- `--role`: Choose `server` or `client`
- `--mode`: Choose `pqc` or `hybrid` (default: `pqc`)
- `--simulate-multiple`: Enable multiple client simulation (client only)

## What Each File Does

### Core Files
- **`main.py`**: Entry point with CLI argument parsing
- **`discovery_client.py`**: Client implementation with key exchange and inventory sending
- **`discovery_server.py`**: Server implementation with key exchange and inventory receiving

### Cryptographic Files
- **`crypto_handler.py`**: Abstract handlers for PQC and Hybrid cryptographic operations
- **`dilithium2_functions.py`**: Dilithium2 (Ml_dsa_44) signature generation and verification
- **`ml_kem_512_functions.py`**: ML-KEM-512 key generation, encapsulation, and decapsulation
- **`ml_kem_768_functions.py`**: ML-KEM-768 key generation, encapsulation, and decapsulation
- **`ml_dsa_65_functions.py`**: ML-DSA-65 signature generation and verification
- **`x25519_functions.py`**: X25519 key generation and secret derivation

### Utility Files
- **`inventory_utils.py`**: Mock inventory data for testing
- **`logger.py`**: Logging configuration and utilities

## Output

- **Server**: Receives and saves inventory to `inventory_received_[IP]_[PORT].txt`
- **Client**: Sends mock inventory with device information

## Performance

- **PQC Mode**: Faster key exchange, smaller key sizes
- **Hybrid Mode**: Enhanced security with classical + quantum-resistant algorithms
- **Multiple Clients**: Both modes supports up to 5 concurrent client connections
