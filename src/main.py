import argparse

def main():
    parser = argparse.ArgumentParser(description="Asset Discovery with PQC/Hybrid support")
    parser.add_argument('--mode', choices=['pqc', 'hybrid'], default='pqc', help='Crypto mode: pqc or hybrid')
    parser.add_argument('--role', choices=['server', 'client'], required=True, help='Run as server or client')
    parser.add_argument('--simulate-multiple', action='store_true', help='Simulate multiple clients (for client role only)')
    args = parser.parse_args()

    if args.role == 'server':
        from src.server.discovery_server import run_server
        run_server(mode=args.mode)
    else:
        from src.client.discovery_client import run_client
        run_client(mode=args.mode, simulate_multiple=args.simulate_multiple)

if __name__ == "__main__":
    main()
