import hashlib


class IntegrityChecker:
    """
    Handles SHA-256 hashing for file integrity verification.

    SHA-256 produces a 256-bit (32-byte / 64 hex character) hash.
    It is deterministic — the same input always produces the same hash.
    It is collision resistant — no two different inputs produce the same hash.
    It is one-way — you cannot reverse a hash to get the original data.
    """

    def compute_hash(self, data: bytes) -> str:
        """
        Computes a SHA-256 hash of the given data.
        Returns it as a hex string (64 characters).

        This is called BEFORE encryption on the sender side.
        The hash is then included in the payload so the receiver
        can verify integrity after decryption.
        """
        hash_value = hashlib.sha256(data).hexdigest()
        print(f"[INTEGRITY] Hash computed: {hash_value[:32]}...")
        return hash_value

    def verify(self, data: bytes, original_hash: str) -> bool:
        """
        Recomputes the hash of data and compares it to the original.
        Called on the receiver side after decryption.

        Returns True if data is intact, False if tampered.
        """
        recomputed = hashlib.sha256(data).hexdigest()

        if recomputed == original_hash:
            print("[INTEGRITY] ✅ Verification passed — file is intact.")
            return True
        else:
            print("[INTEGRITY] ❌ TAMPER DETECTED — hashes do not match!")
            print(f"   Expected : {original_hash[:32]}...")
            print(f"   Got      : {recomputed[:32]}...")
            return False