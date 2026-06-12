import socket


def send_message(sock: socket.socket, data: bytes):
    """
    Sends a length-prefixed message over a socket.

    Format: [4-byte length][data bytes]

    Why length-prefixed?
    TCP is a stream — it has no concept of message boundaries.
    Without this, recv() might return partial data or combine
    multiple messages. The length prefix tells the receiver
    exactly how many bytes belong to this message.
    """
    length_prefix = len(data).to_bytes(4, byteorder='big')
    sock.sendall(length_prefix + data)


def receive_message(sock: socket.socket) -> bytes:
    """
    Receives a complete length-prefixed message from a socket.

    Steps:
    1. Read exactly 4 bytes to get the message length
    2. Read exactly that many bytes to get the full message
    3. Return the complete message

    This blocks until the full message arrives — safe and reliable.
    """
    # Step 1 — read the 4-byte length prefix
    raw_length = _recv_exactly(sock, 4)
    message_length = int.from_bytes(raw_length, byteorder='big')

    # Step 2 — read exactly that many bytes
    return _recv_exactly(sock, message_length)


def _recv_exactly(sock: socket.socket, num_bytes: int) -> bytes:
    """
    Reads exactly num_bytes from the socket, handling partial reads.

    socket.recv() is not guaranteed to return all requested bytes
    in one call — especially for large messages. This loop keeps
    reading until we have exactly what we asked for.
    """
    buffer = b''
    while len(buffer) < num_bytes:
        chunk = sock.recv(num_bytes - len(buffer))
        if not chunk:
            raise ConnectionError("Socket closed before all data was received.")
        buffer += chunk
    return buffer