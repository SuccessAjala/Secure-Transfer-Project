import json
from cryptography_layer.integrity import IntegrityChecker


class PayloadBuilder:
    """
    Builds and parses the data packet sent between sender and receiver.

    Packet structure:
    ┌─────────────────────┬──────────────────────────┬────────────────┐
    │ 4 bytes (meta_len)  │ meta_len bytes (JSON)    │ remaining bytes│
    │ big-endian integer  │ filename + sha256 hash   │ file content   │
    └─────────────────────┴──────────────────────────┴────────────────┘

    Why JSON for metadata?
    - Human readable, easy to debug
    - Easy to extend later (e.g. add file size, timestamp, sender ID)
    - Built into Python standard library, no extra dependencies
    
    Why big-endian for the length prefix?
    - Network byte order is conventionally big-endian
    - Both sender and receiver must agree on byte order or the
      length value will be misread entirely
    """

    def __init__(self):
        self.checker = IntegrityChecker()

    def build(self, file_bytes: bytes, filename: str) -> bytes:
        """
        Packages file bytes + filename + hash into one transmittable payload.

        Steps:
        1. Compute SHA-256 hash of the raw file bytes
        2. Build a JSON metadata string with filename and hash
        3. Encode metadata to bytes
        4. Prepend a 4-byte length prefix so receiver knows where metadata ends
        5. Concatenate: length prefix + metadata + file bytes

        Args:
            file_bytes : raw bytes of the file to send
            filename   : original filename, so receiver can save it correctly

        Returns:
            A single bytes object ready to be encrypted and transmitted
        """
        # Step 1 — hash the file before anything else
        file_hash = self.checker.compute_hash(file_bytes)

        # Step 2 — build metadata dictionary and serialise to JSON bytes
        metadata = {
            "filename": filename,
            "hash": file_hash
        }
        metadata_bytes = json.dumps(metadata).encode('utf-8')

        # Step 3 — pack metadata length as a 4-byte big-endian integer
        # 4 bytes can represent up to 4,294,967,295 — more than enough
        # for any realistic metadata string
        meta_length = len(metadata_bytes).to_bytes(4, byteorder='big')

        # Step 4 — assemble the full payload
        payload = meta_length + metadata_bytes + file_bytes

        print(f"[PAYLOAD] Built payload for '{filename}'.")
        print(f"          Metadata : {len(metadata_bytes)} bytes")
        print(f"          File     : {len(file_bytes)} bytes")
        print(f"          Total    : {len(payload)} bytes")

        return payload

    def parse(self, payload: bytes) -> tuple[str, str, bytes]:
        """
        Unpacks a received payload back into its components.

        Steps:
        1. Read first 4 bytes to get metadata length
        2. Read exactly that many bytes to get the metadata JSON
        3. Everything after is the file content
        4. Parse JSON to extract filename and hash

        Args:
            payload : the raw bytes received from the network

        Returns:
            filename   : original filename
            file_hash  : SHA-256 hash to verify against
            file_bytes : the actual file content
        """
        # Step 1 — read the 4-byte length prefix
        meta_length = int.from_bytes(payload[:4], byteorder='big')

        # Step 2 — slice out exactly the metadata section
        metadata_bytes = payload[4 : 4 + meta_length]
        metadata = json.loads(metadata_bytes.decode('utf-8'))

        # Step 3 — everything after metadata is the file
        file_bytes = payload[4 + meta_length:]

        filename = metadata['filename']
        file_hash = metadata['hash']

        print(f"[PAYLOAD] Parsed payload.")
        print(f"          Filename : {filename}")
        print(f"          Hash     : {file_hash[:32]}...")
        print(f"          File     : {len(file_bytes)} bytes")

        return filename, file_hash, file_bytes