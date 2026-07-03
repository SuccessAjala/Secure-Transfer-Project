from transfer_logger import TransferLogger

logger = TransferLogger()
sessions = logger.get_recent_sessions(10)

if not sessions:
    print("No sessions logged yet.")
else:
    for s in sessions:
        mode = "Encrypted" if s["encrypted"] else "Plaintext"
        status = "⚠️ TAMPERED" if s["tamper_detected"] else "✅ Clean"
        print(f"[{s['session_id']}] {s['timestamp']} | {s['filename']} | {mode} | {status}")
        if s["original_hash"]:
            print(f"         Original hash  : {s['original_hash'][:32]}...")
            print(f"         Recomputed hash: {s['recomputed_hash'][:32]}...")

logger.close()