import threading
import time
import subprocess
import sys
# This script launches both the device (server) and agent (client) in separate threads.
# I use the script to demonstrate the full discovery and inventory signing workflow in one go.

# Function to run the device server (the discovered device)
def run_device():
    print("[Demo] Starting device client (discovered device)...")
    subprocess.run([sys.executable, "device_client.py"])

# Function to run the discovery agent (the scanner)
def run_agent():
    print("[Demo] Starting discovery agent (server)...")
    time.sleep(1)  # Give device server time to bind and listen
    subprocess.run([sys.executable, "discovery_server.py"])

if __name__ == "__main__":
    # Start both device and agent in separate threads
    device_thread = threading.Thread(target=run_device)
    agent_thread = threading.Thread(target=run_agent)

    device_thread.start()
    agent_thread.start()

    device_thread.join()
    agent_thread.join()

    print("\n[Demo] Run complete.")
