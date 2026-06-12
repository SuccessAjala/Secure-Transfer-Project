import socket
import argparse
from cryptography_layer.rsa_handler import RSAHandler
from cryptography_layer.aes_handler import AESHandler
from network.payload import PayloadBuilder
from network.utils import send_message, receive_message
from ack.acknowledgement import AcknowledgementHandler

HOST = '127.0.0.1'
PORT = 5003          # Routes through attacker


def send_file(filepath: str, encrypted: bool = True,
              host: str = HOST, port: int = PORT):
    """
    Connects to the receiver and transmits a file.

    Args:
        filepath  : path to the file to send
        encrypted : if True, full RSA+AES encryption pipeline
                    if False, raw plaintext transmission for comparison
    """
    # Read the file from disk
    with open(filepath, 'rb') as f:
        file_bytes = f.read()

    filename = filepath.split("\\")[-1]
    print(f"[SENDER] Loaded '{filename}' ({len(file_bytes)} bytes).")
    print(f"[SENDER] Mode: {'🔒 ENCRYPTED' if encrypted else '⚠️  UNENCRYPTED (plaintext)'}")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print(f"[SENDER] Connected to receiver at {HOST}:{PORT}.")

    with client_socket:
        if encrypted:
            _send_encrypted(client_socket, file_bytes, filename)
        else:
            _send_plaintext(client_socket, file_bytes, filename)


def _send_encrypted(sock, file_bytes: bytes, filename: str):
    """Full RSA+AES encrypted transfer pipeline."""
    rsa = RSAHandler()
    aes = AESHandler()
    payload_builder = PayloadBuilder()
    ack_handler = AcknowledgementHandler()

    # Announce encrypted mode so receiver knows what to expect
    send_message(sock, b"MODE:ENCRYPTED")

    # Step 1 — receive receiver's public key
    public_key_bytes = receive_message(sock)
    print(f"[SENDER] Received receiver's public key ({len(public_key_bytes)} bytes).")

    # Step 2 — generate and wrap AES session key
    aes_key = aes.generate_key()
    wrapped_aes_key = rsa.wrap_aes_key(aes_key, public_key_bytes)
    send_message(sock, wrapped_aes_key)
    print(f"[SENDER] Wrapped AES key sent.")

    # Step 3 — build, encrypt and send payload
    payload = payload_builder.build(file_bytes, filename)
    iv, ciphertext = aes.encrypt(payload, aes_key)
    send_message(sock, iv)
    send_message(sock, ciphertext)
    print(f"[SENDER] Encrypted payload sent.")

    # Step 4 — verify signed ACK
    ack_bytes = receive_message(sock)
    is_valid, ack_status = ack_handler.verify_signed_ack(ack_bytes, public_key_bytes)

    if not is_valid:
        print(f"[SENDER] ❌ ACK signature invalid — ACK may have been forged by attacker!")
    elif ack_status == "ACK:OK":
        print(f"[SENDER] ✅ Transfer confirmed — file received intact.")
    else:
        print(f"[SENDER] ⚠️  Transfer failed — receiver detected tampering!")


def _send_plaintext(sock, file_bytes: bytes, filename: str):
    """
    Raw plaintext transfer — no encryption, no key exchange.
    Used to demonstrate what an attacker sees without encryption.

    Sends:
    1. A mode flag so receiver knows to expect plaintext
    2. The filename
    3. The raw file bytes
    """
    # Tell receiver we are in plaintext mode
    send_message(sock, b"MODE:PLAINTEXT")

    # Send filename so receiver knows what to save it as
    send_message(sock, filename.encode('utf-8'))

    # Send raw file bytes — no encryption at all
    send_message(sock, file_bytes)
    print(f"[SENDER] Raw plaintext file sent — contents fully exposed on the wire.")

    # Wait for simple ACK
    ack = receive_message(sock)
    print(f"[SENDER] Acknowledgement received: {ack.decode()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure File Sender")
    parser.add_argument("--file", type=str, default="test_file.txt",
                        help="Path to the file to send")
    parser.add_argument("--mode", choices=["encrypted", "unencrypted"],
                        default="encrypted",
                        help="Transfer mode: encrypted (default) or unencrypted")
    args = parser.parse_args()

    send_file(args.file, encrypted=(args.mode == "encrypted"))