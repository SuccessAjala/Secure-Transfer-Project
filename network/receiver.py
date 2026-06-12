import socket
import os
from cryptography_layer.rsa_handler import RSAHandler
from cryptography_layer.aes_handler import AESHandler
from cryptography_layer.integrity import IntegrityChecker
from network.payload import PayloadBuilder
from network.utils import send_message, receive_message
from ack.acknowledgement import AcknowledgementHandler

SAVE_DIRECTORY = "received_files"
HOST = '127.0.0.1'
PORT = 5002


def start_receiver(host: str = HOST, port: int = PORT):
    """
    Starts the receiver server.
    Handles both encrypted and plaintext transfer modes.
    Detects mode automatically from the first message received.
    """
    os.makedirs(SAVE_DIRECTORY, exist_ok=True)

    rsa = RSAHandler()
    aes = AESHandler()
    payload_builder = PayloadBuilder()
    ack_handler = AcknowledgementHandler()
    checker = IntegrityChecker()

    rsa.generate_keypair()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1)

    print(f"[RECEIVER] Listening on {host}:{port}...")
    print(f"[RECEIVER] Waiting for sender to connect...")

    conn, addr = server_socket.accept()
    print(f"[RECEIVER] Connected to sender at {addr}")

    with conn:
        # Peek at the first message to detect transfer mode
        first_message = receive_message(conn)

        if first_message == b"MODE:PLAINTEXT":
            print(f"[RECEIVER] ⚠️  Plaintext mode detected — no encryption in use.")
            _receive_plaintext(conn, SAVE_DIRECTORY)
        elif first_message == b"MODE:ENCRYPTED":
            print(f"[RECEIVER] 🔒 Encrypted mode detected.")
            _receive_encrypted(conn, rsa, aes, payload_builder,
                               ack_handler, checker, SAVE_DIRECTORY)
        else:
            print(f"[RECEIVER] ❌ Unknown mode — closing connection.")

    server_socket.close()
    print("[RECEIVER] Connection closed.")


def _receive_encrypted(conn, rsa, aes, payload_builder,
                       ack_handler, checker, save_dir):
    """Full encrypted receive pipeline."""

    # Send public key to sender
    public_key_bytes = rsa.export_public_key()
    send_message(conn, public_key_bytes)
    print(f"[RECEIVER] Public key sent to sender.")

    # Receive and unwrap AES key
    wrapped_aes_key = receive_message(conn)
    print(f"[RECEIVER] Received wrapped AES key ({len(wrapped_aes_key)} bytes).")
    aes_key = rsa.unwrap_aes_key(wrapped_aes_key)

    # Receive IV and ciphertext
    iv = receive_message(conn)
    ciphertext = receive_message(conn)
    print(f"[RECEIVER] Received encrypted payload ({len(ciphertext)} bytes).")

    # Decrypt
    decrypted_payload = aes.decrypt(iv, ciphertext, aes_key)

    # Parse and verify
    try:
        filename, received_hash, file_bytes = payload_builder.parse(decrypted_payload)
        is_intact = checker.verify(file_bytes, received_hash)

        if is_intact:
            save_path = os.path.join(save_dir, filename)
            with open(save_path, 'wb') as f:
                f.write(file_bytes)
            print(f"[RECEIVER] ✅ File saved to '{save_path}'.")
            ack = ack_handler.create_signed_ack("ACK:OK", rsa.private_key)
            send_message(conn, ack)
        else:
            print(f"[RECEIVER] ❌ File rejected — integrity check failed.")
            ack = ack_handler.create_signed_ack("ACK:TAMPERED", rsa.private_key)
            send_message(conn, ack)

    except Exception as e:
        print(f"[RECEIVER] ❌ TAMPER DETECTED — payload unparseable: {e}")
        ack = ack_handler.create_signed_ack("ACK:TAMPERED", rsa.private_key)
        send_message(conn, ack)


def _receive_plaintext(conn, save_dir):
    """
    Plaintext receive pipeline.
    No decryption — just read filename and raw bytes directly.
    """
    # Receive filename
    filename = receive_message(conn).decode('utf-8')
    print(f"[RECEIVER] Receiving file: '{filename}'")

    # Receive raw file bytes
    file_bytes = receive_message(conn)
    print(f"[RECEIVER] Received {len(file_bytes)} bytes of plaintext data.")

    # Save directly
    save_path = os.path.join(save_dir, f"plain_{filename}")
    with open(save_path, 'wb') as f:
        f.write(file_bytes)
    print(f"[RECEIVER] File saved to '{save_path}'.")

    send_message(conn, b"ACK:OK")


if __name__ == "__main__":
    start_receiver()