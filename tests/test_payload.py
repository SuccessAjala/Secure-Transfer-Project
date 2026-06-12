from network.payload import PayloadBuilder
from cryptography_layer.integrity import IntegrityChecker

builder = PayloadBuilder()
checker = IntegrityChecker()

# Simulate a file being read from disk
original_file = b"Confidential report data. " * 20
filename = "report.txt"

print("=== Building Payload ===")
payload = builder.build(original_file, filename)

print("\n=== Parsing Payload ===")
recovered_filename, received_hash, recovered_file = builder.parse(payload)

print("\n=== Verifying Integrity ===")
is_intact = checker.verify(recovered_file, received_hash)

assert recovered_filename == filename
assert recovered_file == original_file
assert is_intact == True

print("\n✅ Payload test passed!")
print(f"   Filename  : {recovered_filename}")
print(f"   File match: {recovered_file == original_file}")