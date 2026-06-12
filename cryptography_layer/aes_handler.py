from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class AESHandler:
    """
    Handles AES-256 encryption and decryption in CBC mode.

    Key size: 32 bytes = 256 bits
    Block size: 16 bytes (fixed by AES standard)
    IV size: 16 bytes (must match block size)
    """

    KEY_SIZE = 32   # 256 bits
    BLOCK_SIZE = 16 # AES block size is always 16 bytes

    def generate_key(self) -> bytes:
        """
        Generates a cryptographically secure random 32-byte AES key.
        This is the session key — generated fresh for every file transfer.
        Never reuse the same key for multiple transfers.
        """
        key = get_random_bytes(self.KEY_SIZE)
        print(f"[AES] Session key generated. Size: {len(key)} bytes ({len(key)*8} bits).")
        return key

    def _pad(self, data: bytes) -> bytes:
        """
        Pads data so its length is a multiple of 16 bytes.

        AES-CBC requires input to be exactly a multiple of the block size.
        We use PKCS7 padding: if you need N bytes of padding, each padding
        byte has the value N.

        Example: if data is 13 bytes, you need 3 bytes of padding.
        Padding added: b'\\x03\\x03\\x03'
        If data is already a multiple of 16, a full extra block is added
        so the receiver always knows padding is present.
        """
        pad_length = self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE)
        padding = bytes([pad_length] * pad_length)
        return data + padding

    def _unpad(self, data: bytes) -> bytes:
        """
        Removes PKCS7 padding after decryption.
        Reads the last byte to find out how many padding bytes to strip.
        """
        pad_length = data[-1]
        return data[:-pad_length]

    def encrypt(self, plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
        """
        Encrypts data using AES-256-CBC.

        Steps:
        1. Generate a fresh random IV
        2. Pad the plaintext to a multiple of 16 bytes
        3. Encrypt using AES-CBC with the key and IV
        4. Return IV and ciphertext separately
           (IV must be sent alongside ciphertext so receiver can decrypt)

        Returns:
            iv         -- 16 random bytes, sent in plaintext with the message
            ciphertext -- the encrypted data
        """
        iv = get_random_bytes(self.BLOCK_SIZE)
        padded = self._pad(plaintext)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded)

        print(f"[AES] Encrypted. Original size: {len(plaintext)} bytes → "
              f"Ciphertext size: {len(ciphertext)} bytes. IV: {iv.hex()[:16]}...")
        return iv, ciphertext

    def decrypt(self, iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
        """
        Decrypts AES-256-CBC ciphertext back to original plaintext.

        Steps:
        1. Recreate the cipher using the same key and IV
        2. Decrypt the ciphertext
        3. Remove padding to recover original data

        Note: AES-CBC decryption requires the exact same IV that was
        used during encryption — this is why we send it with the message.
        """
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = self._unpad(padded_plaintext)

        print(f"[AES] Decrypted. Recovered size: {len(plaintext)} bytes.")
        return plaintext