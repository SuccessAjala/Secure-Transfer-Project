import sys
sys.path.append('..')  # So Python can find the crypto folder

from cryptography_layer.rsa_handler import RSAHandler

# Simulate receiver generating keys
receiver = RSAHandler()
receiver.generate_keypair()

# Receiver shares public key (as bytes, like it would over a network)
public_key_bytes = receiver.export_public_key()

# Simulate sender wrapping a fake AES key
sender = RSAHandler()
fake_aes_key = b'\x01' * 32  # 32 bytes of 0x01 — just for testing

wrapped = sender.wrap_aes_key(fake_aes_key, public_key_bytes)

# Receiver unwraps it
recovered_key = receiver.unwrap_aes_key(wrapped)

# Verify
assert recovered_key == fake_aes_key, "Keys don't match!"
print(f"\n✅ Test passed! Original: {fake_aes_key.hex()}")
print(f"✅ Recovered: {recovered_key.hex()}")