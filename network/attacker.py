import socket
from network.utils import send_message, receive_message

# Default constants — used when running directly, not through main.py
ATTACKER_HOST = '127.0.0.1'
ATTACKER_PORT = 5003
RECEIVER_HOST = '127.0.0.1'
RECEIVER_PORT = 5002


def corrupt_bytes(data: bytes, position: int = 100) -> bytes:
    """
    Flips all bits in one byte at the given position.

    XOR with 0xFF flips every bit:
    e.g. 10110010 XOR 11111111 = 01001101

    We target a position deep in the data (default 100)
    to ensure we're hitting the ciphertext, not the length
    prefix or metadata.

    This simulates an attacker making a small, targeted
    modification hoping it goes unnoticed.
    """
    corrupted = bytearray(data)
    corrupted[position] ^= 0xFF
    return bytes(corrupted)


def start_attacker(tamper: bool = False,
                   attacker_host: str = ATTACKER_HOST,
                   attacker_port: int = ATTACKER_PORT,
                   receiver_host: str = RECEIVER_HOST,
                   receiver_port: int = RECEIVER_PORT):
    """
    Starts the MITM proxy.
    Auto-detects encrypted vs plaintext mode from the first message.

    Args:
        tamper        : if True, flips bytes in the ciphertext
        attacker_host : host/IP to listen on
        attacker_port : port to listen on (sender connects here)
        receiver_host : host/IP of the real receiver
        receiver_port : port of the real receiver
    """
    mode = "ACTIVE (tampering)" if tamper else "PASSIVE (eavesdropping)"
    print(f"[ATTACKER] Starting in {mode} mode.")
    print(f"[ATTACKER] Listening on port {attacker_port}, "
          f"forwarding to {receiver_host}:{receiver_port}.")

    attacker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    attacker_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    attacker_socket.bind((attacker_host, attacker_port))
    attacker_socket.listen(1)

    print(f"[ATTACKER] Waiting for sender to connect...")
    sender_conn, sender_addr = attacker_socket.accept()
    print(f"[ATTACKER] Sender connected from {sender_addr}.")

    receiver_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receiver_conn.connect((receiver_host, receiver_port))
    print(f"[ATTACKER] Connected to receiver at {receiver_host}:{receiver_port}.")

    with sender_conn, receiver_conn:
        # Peek at first message to detect mode
        first_message = receive_message(sender_conn)

        if first_message == b"MODE:PLAINTEXT":
            print(f"\n[ATTACKER] ⚠️  PLAINTEXT mode detected — contents fully visible!")
            send_message(receiver_conn, first_message)
            _intercept_plaintext(sender_conn, receiver_conn)
        elif first_message == b"MODE:ENCRYPTED":
            print(f"\n[ATTACKER] 🔒 Encrypted mode detected.")
            send_message(receiver_conn, first_message)
            _intercept_encrypted(sender_conn, receiver_conn, tamper)
        else:
            print(f"\n[ATTACKER] ❌ Unknown mode received.")

    attacker_socket.close()
    print("\n[ATTACKER] Session complete.")


def _intercept_plaintext(sender_conn, receiver_conn):
    """
    Intercepts a plaintext transfer.
    Can read everything — filename and full file contents.
    """
    # Intercept filename
    filename = receive_message(sender_conn)
    print(f"[ATTACKER] Filename intercepted: {filename.decode('utf-8')}")
    send_message(receiver_conn, filename)

    # Intercept raw file bytes — fully readable
    file_bytes = receive_message(sender_conn)
    print(f"\n[ATTACKER] ======= FILE CONTENTS INTERCEPTED =======")
    print(f"[ATTACKER] Size: {len(file_bytes)} bytes")
    print(f"[ATTACKER] Contents:\n")
    print(file_bytes.decode('utf-8', errors='replace'))
    print(f"[ATTACKER] ==========================================")
    send_message(receiver_conn, file_bytes)

    # Forward ACK
    ack = receive_message(receiver_conn)
    print(f"\n[ATTACKER] ACK intercepted: {ack.decode()}. Forwarding to sender.")
    send_message(sender_conn, ack)


def _intercept_encrypted(sender_conn, receiver_conn, tamper):
    """
    Intercepts an encrypted transfer.
    Sees only noise — cannot read key or file contents.
    """
    # --- Message 1: Receiver's RSA public key → forward to sender ---
    print("\n[ATTACKER] Intercepting RSA public key from receiver...")
    public_key = receive_message(receiver_conn)
    print(f"[ATTACKER] Public key intercepted ({len(public_key)} bytes). Forwarding...")
    send_message(sender_conn, public_key)

    # --- Message 2: Wrapped AES key → forward to receiver ---
    print("\n[ATTACKER] Intercepting wrapped AES key from sender...")
    wrapped_aes_key = receive_message(sender_conn)
    print(f"[ATTACKER] Wrapped AES key intercepted ({len(wrapped_aes_key)} bytes).")
    print(f"[ATTACKER] Attempting to read AES key contents...")
    print(f"[ATTACKER] Raw bytes (first 32): {wrapped_aes_key[:32].hex()}")
    print(f"[ATTACKER] Looks like: {wrapped_aes_key[:32]}")
    print(f"[ATTACKER] ❌ Cannot decrypt — protected by RSA-2048. Forwarding unchanged...")
    send_message(receiver_conn, wrapped_aes_key)

    # --- Message 3: IV → forward to receiver ---
    print("\n[ATTACKER] Intercepting IV from sender...")
    iv = receive_message(sender_conn)
    print(f"[ATTACKER] IV intercepted ({len(iv)} bytes). Forwarding...")
    send_message(receiver_conn, iv)

    # --- Message 4: Ciphertext → tamper or forward ---
    print("\n[ATTACKER] Intercepting ciphertext from sender...")
    ciphertext = receive_message(sender_conn)
    print(f"[ATTACKER] Ciphertext intercepted ({len(ciphertext)} bytes).")
    print(f"[ATTACKER] Attempting to read file contents...")
    print(f"[ATTACKER] Raw bytes (first 32): {ciphertext[:32].hex()}")
    print(f"[ATTACKER] Looks like: {ciphertext[:32]}")
    print(f"[ATTACKER] ❌ Cannot read — AES-256 encrypted. Indistinguishable from random noise.")

    if tamper:
        print(f"[ATTACKER] ⚠️  TAMPERING — flipping byte at position 100...")
        ciphertext = corrupt_bytes(ciphertext, position=100)
        print(f"[ATTACKER] Modified ciphertext forwarded to receiver.")
    else:
        print(f"[ATTACKER] Passive mode — forwarding ciphertext unchanged.")

    send_message(receiver_conn, ciphertext)

    # --- Message 5: Signed ACK → forward back to sender ---
    print("\n[ATTACKER] Intercepting ACK from receiver...")
    ack = receive_message(receiver_conn)
    print(f"[ATTACKER] ACK intercepted: {ack.decode()}. Forwarding to sender.")
    send_message(sender_conn, ack)


if __name__ == "__main__":
    import sys
    tamper_mode = len(sys.argv) > 1 and sys.argv[1] == "tamper"
    start_attacker(tamper=tamper_mode)