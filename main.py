import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        description="CNS Secure File Transfer — Proof of Concept",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  Start receiver:
    python main.py --role receiver

  Start attacker (passive):
    python main.py --role attacker

  Start attacker (active/tamper):
    python main.py --role attacker --tamper

  Send a file (encrypted):
    python main.py --role sender --file test_file.txt --mode encrypted

  Send a file (unencrypted):
    python main.py --role sender --file test_file.txt --mode unencrypted

  Multi-machine (specify IPs):
    python main.py --role receiver --host 192.168.1.8 --port 5002
    python main.py --role attacker --receiver-host 192.168.1.8 --receiver-port 5002 --host 192.168.1.5 --port 5003
    python main.py --role sender --host 192.168.1.5 --port 5003 --file report.txt
        """
    )

    # --- Required argument ---
    parser.add_argument(
        "--role",
        choices=["sender", "receiver", "attacker"],
        required=True,
        help="Role to run: sender, receiver, or attacker"
    )

    # --- Sender arguments ---
    parser.add_argument(
        "--file",
        type=str,
        default="test_file.txt",
        help="(Sender) Path to the file to send (default: test_file.txt)"
    )
    parser.add_argument(
        "--mode",
        choices=["encrypted", "unencrypted"],
        default="encrypted",
        help="(Sender) Transfer mode (default: encrypted)"
    )

    # --- Attacker arguments ---
    parser.add_argument(
        "--tamper",
        action="store_true",
        help="(Attacker) Enable active tampering mode"
    )

    # --- Network arguments ---
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host/IP to bind or connect to (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port to bind or connect to (default: 5002 for receiver, 5003 for attacker/sender)"
    )
    parser.add_argument(
        "--receiver-host",
        type=str,
        default="127.0.0.1",
        help="(Attacker) Host/IP of the real receiver (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--receiver-port",
        type=int,
        default=5002,
        help="(Attacker) Port of the real receiver (default: 5002)"
    )

    args = parser.parse_args()

    # --- Route to the correct module ---
    if args.role == "receiver":
        port = args.port or 5002
        _run_receiver(args.host, port)

    elif args.role == "attacker":
        port = args.port or 5003
        _run_attacker(
            host=args.host,
            port=port,
            receiver_host=args.receiver_host,
            receiver_port=args.receiver_port,
            tamper=args.tamper
        )

    elif args.role == "sender":
        port = args.port or 5003
        _run_sender(
            host=args.host,
            port=port,
            filepath=args.file,
            encrypted=(args.mode == "encrypted")
        )


def _run_receiver(host: str, port: int):
    import network.receiver as receiver_module
    print(f"[MAIN] Starting receiver on {host}:{port}")
    receiver_module.start_receiver(host=host, port=port)


def _run_attacker(host: str, port: int, receiver_host: str,
                  receiver_port: int, tamper: bool):
    import network.attacker as attacker_module
    print(f"[MAIN] Starting attacker on {host}:{port} "
          f"→ forwarding to {receiver_host}:{receiver_port}")
    attacker_module.start_attacker(
        tamper=tamper,
        attacker_host=host,
        attacker_port=port,
        receiver_host=receiver_host,
        receiver_port=receiver_port
    )


def _run_sender(host: str, port: int, filepath: str, encrypted: bool):
    import network.sender as sender_module
    print(f"[MAIN] Starting sender → connecting to {host}:{port}")
    sender_module.send_file(filepath, encrypted=encrypted, host=host, port=port)

if __name__ == "__main__":
    main()