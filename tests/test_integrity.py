from cryptography_layer.integrity import IntegrityChecker

checker = IntegrityChecker()

original_data = b"This is the original file content. Nothing has changed."

# --- Scenario 1: Clean transfer ---
print("=== Scenario 1: Clean Transfer ===")
hash_before = checker.compute_hash(original_data)

# Simulate data arriving exactly as sent
received_data = original_data
result = checker.verify(received_data, hash_before)
assert result == True

# --- Scenario 2: Tampered transfer ---
print("\n=== Scenario 2: Tampered Transfer (MITM Attack) ===")
hash_before = checker.compute_hash(original_data)

# Simulate attacker flipping one byte in the middle of the data
tampered_data = bytearray(original_data)
tampered_data[10] ^= 0xFF          # XOR flips all bits in byte at position 10
tampered_data = bytes(tampered_data)

result = checker.verify(tampered_data, hash_before)
assert result == False

print("\n✅ Both scenarios behaved correctly.")