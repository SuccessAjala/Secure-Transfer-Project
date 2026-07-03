from transfer_logger import TransferLogger

logger = TransferLogger()

# Log a clean session
print("=== Logging clean session ===")
session_id = logger.log_session(
    filename        = "test_file.txt",
    file_size       = 280,
    sender_host     = "127.0.0.1",
    receiver_host   = "127.0.0.1",
    encrypted       = True,
    tamper_detected = False
)
logger.log_integrity(
    session_id      = session_id,
    original_hash   = "abc123",
    recomputed_hash = "abc123",
    tamper_detected = False
)

# Log a tampered session
print("\n=== Logging tampered session ===")
session_id = logger.log_session(
    filename        = "test_file.txt",
    file_size       = 280,
    sender_host     = "127.0.0.1",
    receiver_host   = "127.0.0.1",
    encrypted       = True,
    tamper_detected = True
)
logger.log_integrity(
    session_id      = session_id,
    original_hash   = "abc123",
    recomputed_hash = "xyz999",
    tamper_detected = True
)

# Retrieve and display
print("\n=== Recent Sessions ===")
sessions = logger.get_recent_sessions(limit=5)
for s in sessions:
    print(f"  [{s['session_id']}] {s['timestamp']} | "
          f"{s['filename']} | "
          f"{'Encrypted' if s['encrypted'] else 'Plaintext'} | "
          f"{'⚠️ TAMPERED' if s['tamper_detected'] else '✅ Clean'}")

logger.close()
print("\n✅ Logger test passed.")