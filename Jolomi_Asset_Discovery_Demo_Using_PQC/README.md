# Asset Discovery Using Post-Quantum Cryptography - Demo Report

## Objective

To simulate how asset discovery agents can be protected against quantum threats by replacing classical key exchange and authentication methods (e.g., RSA, ECC) with **post-quantum algorithms** — specifically, **ML-KEM (Kyber)** for key encapsulation and **Dilithium** for digital signatures.

The system ensures that **before any device scanning or communication begins**, a PQC-secured connection is established between the discovery agent and the remote machine.

---

## System Architecture

### 🔹 Target Device (Ubuntu VM)

Simulates a protected enterprise asset running:

* SSH service (OpenSSH)
* TLS service (optional OpenSSL endpoint)
* SNMP agent (`snmpd`)
* Flask API serving mock connected device data
* PQC server using `ML-KEM_512` and `Dilithium2`

### 🔹 Host Machine (Windows/Linux/macOS)

Runs the discovery system:

* `pqc_client_connection.py` for post-quantum key exchange and signature verification
* `discovery_agent.py` which performs:

  * TLS scan
  * SSH banner grab
  * SNMP query
  * Retrieval of internal asset data via Flask

> **Note:** All operations are blocked until the **PQC handshake** is successfully completed.

---

## 💪 Demo Flow

### Setup the Ubuntu VM

1. Install essential services (SSH, SNMP, Flask)
2. Create a mock JSON file of connected devices
3. Start the Flask API to serve mock asset data
4. Launch the PQC server which:

   * Receives the client's Kyber public key
   * Sends back the ciphertext, shared secret, and a Dilithium signature

### Run Discovery from Host Machine

1. Agent first connects to the PQC server
2. Upon **successful ML-KEM decapsulation** and **Dilithium signature verification**:

   * Begins discovery operations (TLS, SSH, SNMP, and Flask API)
   * Results are saved to a structured file (`pqc_secure_discovery.json`)

---

## Results

The demo produces the following report:

**File:** `pqc_secure_discovery.json`

**Contents:**

* TLS scan status (if reachable)
* SSH banner from the VM
* SNMP query response
* List of internal connected devices (from Flask)

> **All actions only occur after a successful post-quantum cryptographic handshake.**

---

## Note on Local Testing

This demo can also be performed on a **single machine** without a virtual machine:

* Change the IP address in the scripts to `localhost`
* Open two terminal windows:

  * One for the PQC server and Flask API
  * Another for the discovery agent and client

This allows anyone to reproduce the setup even without virtualization.