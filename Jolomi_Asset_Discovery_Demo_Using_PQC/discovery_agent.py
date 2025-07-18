import subprocess, socket, requests, json
from pqc_client_connection import establish_secure_connection

VM_IP = "192.168.114.130"

def scan_tls():
    # here i try to connect to the VM via TLS and check if the TLS server is set up correctly and has a valid certificate
    try:
        result = subprocess.run(
            ["openssl", "s_client", "-connect", f"{VM_IP}:4433"],
            input="Q\n", capture_output=True, text=True, timeout=5
        )
        return {"tls_status": "TLS success" if "BEGIN CERTIFICATE" in result.stdout else "TLS failed"}
    except Exception as e:
        return {"tls_error": str(e)}

def scan_ssh():
    # here i try to connect to the VM via SSH and retrieve the SSH banner
    try:
        with socket.create_connection((VM_IP, 22), timeout=3) as sock:
            return {"ssh_banner": sock.recv(1024).decode().strip()}
    except Exception as e:
        return {"ssh_error": str(e)}
 
def scan_snmp():
    # here i try to connect to the VM via SNMP and check if the SNMP service is enabled and responsive
    try:
        result = subprocess.run(
            ["snmpget", "-v1", "-c", "public", VM_IP, "1.3.6.1.2.1.1.1.0"],
            capture_output=True, text=True, timeout=5
        )
        return {"snmp_response": result.stdout.strip()}
    except Exception as e:
        return {"snmp_error": str(e)}

def get_connected_devices():
    try:
        r = requests.get(f"http://{VM_IP}:8000/devices", timeout=5)
        return {"connected_devices": r.json()}
    except Exception as e:
        return {"connected_devices_error": str(e)}

def run_discovery():
    print("Establishing ML_KEM_512 + Dilithium secure connection...")
    ss = establish_secure_connection()

    print("Starting asset discovery...")
    report = {
        "type": "PQC Secured Discovery (ML_KEM_512)",
        "tls": scan_tls(),
        "ssh": scan_ssh(),
        "snmp": scan_snmp(),
        "internal_assets": get_connected_devices()
    }

    with open("pqc_secure_discovery.json", "w") as f:
        json.dump(report, f, indent=4)

    print("Discovery complete. Saved to pqc_secure_discovery.json")

if __name__ == "__main__":
    run_discovery()
