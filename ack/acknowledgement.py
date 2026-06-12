from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import json
import time


class AcknowledgementHandler:
    """
    Handles creation and verification of RSA-signed acknowledgements.

    Why sign the ACK?
    A plain text ACK:OK can be forged or modified by an attacker.
    An RSA signature mathematically binds the ACK content to the
    receiver's private key — any modification invalidates it.

    Structure of a signed ACK:
    {
        "status"    : "ACK:OK" or "ACK:TAMPERED",
        "timestamp" : unix timestamp (prevents replay attacks),
        "signature" : hex-encoded RSA signature of status+timestamp
    }

    Why include a timestamp?
    Without it, an attacker could capture a legitimate ACK:OK from
    a previous session and replay it to fool the sender. The timestamp
    makes every ACK unique — a replayed ACK will have an old timestamp
    that the sender can reject.
    """

    def create_signed_ack(self, status: str, private_key) -> bytes:
        """
        Creates a signed acknowledgement message.

        Steps:
        1. Build a message from status + current timestamp
        2. Hash the message with SHA-256
        3. Sign the hash with the receiver's private key
        4. Bundle status, timestamp, and signature into JSON
        5. Return as bytes ready to send

        Args:
            status      : "ACK:OK" or "ACK:TAMPERED"
            private_key : receiver's RSA private key object

        Returns:
            JSON bytes containing status, timestamp, and signature
        """
        # Step 1 — build the message to sign
        timestamp = str(int(time.time()))
        message = f"{status}:{timestamp}".encode('utf-8')

        # Step 2 — hash the message
        # We sign the hash rather than the raw message — standard practice
        message_hash = SHA256.new(message)

        # Step 3 — sign with private key using PKCS#1 v1.5 scheme
        signature = pkcs1_15.new(private_key).sign(message_hash)

        # Step 4 — bundle everything into JSON
        ack_package = {
            "status"    : status,
            "timestamp" : timestamp,
            "signature" : signature.hex()  # Convert bytes to hex for JSON
        }

        ack_bytes = json.dumps(ack_package).encode('utf-8')
        print(f"[ACK] Signed ACK created.")
        print(f"      Status    : {status}")
        print(f"      Timestamp : {timestamp}")
        print(f"      Signature : {signature.hex()[:32]}...")
        return ack_bytes

    def verify_signed_ack(self, ack_bytes: bytes, public_key_bytes: bytes) -> tuple[bool, str]:
        """
        Verifies a signed acknowledgement from the receiver.

        Steps:
        1. Parse the JSON to extract status, timestamp, signature
        2. Reconstruct the original message (status + timestamp)
        3. Hash it the same way the receiver did
        4. Verify the signature against the hash using the public key
        5. Return verification result and status string

        Args:
            ack_bytes        : raw bytes received from network
            public_key_bytes : receiver's public key (received at start of session)

        Returns:
            (is_valid, status) tuple
            is_valid : True if signature checks out, False if forged/tampered
            status   : the ACK status string if valid
        """
        try:
            # Step 1 — parse JSON
            ack_package = json.loads(ack_bytes.decode('utf-8'))
            status    = ack_package['status']
            timestamp = ack_package['timestamp']
            signature = bytes.fromhex(ack_package['signature'])

            # Step 2 — reconstruct the signed message
            message = f"{status}:{timestamp}".encode('utf-8')

            # Step 3 — hash it
            message_hash = SHA256.new(message)

            # Step 4 — verify signature using receiver's public key
            public_key = RSA.import_key(public_key_bytes)
            pkcs1_15.new(public_key).verify(message_hash, signature)

            # If we reach here, signature is valid
            print(f"[ACK] ✅ Signature verified — ACK is authentic.")
            print(f"      Status    : {status}")
            print(f"      Timestamp : {timestamp}")
            return True, status

        except (ValueError, KeyError) as e:
            # Signature verification failed — ACK was forged or modified
            print(f"[ACK] ❌ Signature verification FAILED — ACK may be forged!")
            print(f"      Error: {e}")
            return False, "ACK:INVALID"