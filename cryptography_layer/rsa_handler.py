from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


class RSAHandler:
    """
    Handles RSA-2048 key generation and AES key wrapping/unwrapping.

    Why 2048 bits? It's the minimum recommended key size for secure
    asymmetric encryption. Larger = more secure but slower.
    """

    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keypair(self):
        """
        Generates a fresh RSA-2048 key pair.
        Call this once per session on the receiver side.
        """
        key = RSA.generate(2048)
        self.private_key = key             # Keep this SECRET — never send it
        self.public_key = key.publickey()  # This is safe to share openly
        print("[RSA] Key pair generated successfully.")

    def export_public_key(self) -> bytes:
        """
        Exports the public key as bytes so it can be sent over the network.
        PEM format is the standard — it's the '-----BEGIN PUBLIC KEY-----' format.
        """
        return self.public_key.export_key(format='PEM')

    def wrap_aes_key(self, aes_key: bytes, public_key_bytes: bytes) -> bytes:
        """
        Encrypts (wraps) the AES key using the receiver's public key.
        Only the receiver's private key can decrypt this.

        PKCS1_OAEP is the padding scheme — it adds randomness so
        encrypting the same AES key twice gives different results,
        which prevents pattern attacks.
        """
        pub_key = RSA.import_key(public_key_bytes)
        cipher = PKCS1_OAEP.new(pub_key)
        wrapped = cipher.encrypt(aes_key)
        print(f"[RSA] AES key wrapped. Wrapped size: {len(wrapped)} bytes.")
        return wrapped

    def unwrap_aes_key(self, wrapped_key: bytes) -> bytes:
        """
        Decrypts (unwraps) the AES key using our own private key.
        Only the receiver calls this — they're the only one with the private key.
        """
        if self.private_key is None:
            raise ValueError("No private key loaded. Did you call generate_keypair()?")
        cipher = PKCS1_OAEP.new(self.private_key)
        aes_key = cipher.decrypt(wrapped_key)
        print("[RSA] AES key unwrapped successfully.")
        return aes_key