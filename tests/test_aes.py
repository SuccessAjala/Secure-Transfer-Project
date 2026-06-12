from cryptography_layer.aes_handler import AESHandler

aes = AESHandler()

# Step 1: Generate a session key
key = aes.generate_key()

# Step 2: Simulate a file as bytes
# In reality this will be read from disk — for now we use a string
original_data = b"This is a secret file. It contains sensitive information. " * 10

# Step 3: Encrypt
iv, ciphertext = aes.encrypt(original_data, key)

# Step 4: Decrypt
recovered_data = aes.decrypt(iv, ciphertext, key)

# Step 5: Verify
assert recovered_data == original_data, "Data mismatch after decryption!"
print(f"\n✅ Test passed!")
print(f"   Original : {original_data[:40]}...")
print(f"   Recovered: {recovered_data[:40]}...")
print(f"\n   IV (hex)        : {iv.hex()}")
print(f"   Ciphertext (hex): {ciphertext.hex()[:64]}...")