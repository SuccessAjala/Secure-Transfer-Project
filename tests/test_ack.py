import json
from ack.acknowledgement import AcknowledgementHandler
from cryptography_layer.rsa_handler import RSAHandler
from ack.acknowledgement import AcknowledgementHandler
from cryptography_layer.rsa_handler import RSAHandler

rsa = RSAHandler()
rsa.generate_keypair()
public_key_bytes = rsa.export_public_key()

ack_handler = AcknowledgementHandler()

# --- Scenario 1: Valid signed ACK ---
print("=== Scenario 1: Valid Signed ACK ===")
signed_ack = ack_handler.create_signed_ack("ACK:OK", rsa.private_key)
is_valid, status = ack_handler.verify_signed_ack(signed_ack, public_key_bytes)
assert is_valid == True
assert status == "ACK:OK"

# --- Scenario 2: Forged ACK (attacker intercepts TAMPERED, changes it to OK) ---
print("\n=== Scenario 2: Forged ACK ===")

# Receiver originally sent ACK:TAMPERED
signed_tampered_ack = ack_handler.create_signed_ack("ACK:TAMPERED", rsa.private_key)

# Attacker intercepts it and changes status to ACK:OK
ack_package = json.loads(signed_tampered_ack.decode('utf-8'))
ack_package['status'] = "ACK:OK"          # Attacker swaps TAMPERED → OK
forged_ack = json.dumps(ack_package).encode('utf-8')

# Sender verifies — should catch the forgery
is_valid, status = ack_handler.verify_signed_ack(forged_ack, public_key_bytes)
assert is_valid == False

print("\n✅ All ACK tests passed.")