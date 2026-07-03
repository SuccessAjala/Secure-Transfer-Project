import sqlite3
import os
import time
from datetime import datetime


# Database file lives at the project root
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "transfer_log.db")


class TransferLogger:
    """
    Logs every file transfer session to a local SQLite database.

    Two tables as defined in the ERD:
        TransferSession — records session details
        IntegrityLog    — records integrity verification outcome

    One-to-one relationship: every session has exactly one integrity log.

    The database file (transfer_log.db) is created automatically
    the first time this class is instantiated.
    """

    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH)
        self._create_tables()

    def _create_tables(self):
        """
        Creates the two tables if they don't already exist.
        Safe to call every time — CREATE TABLE IF NOT EXISTS
        won't overwrite existing data.
        """
        cursor = self.conn.cursor()

        # TransferSession table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS TransferSession (
                session_id      INTEGER PRIMARY KEY AUTOINCREMENT,
                filename        TEXT    NOT NULL,
                file_size       INTEGER NOT NULL,
                sender_host     TEXT    NOT NULL,
                receiver_host   TEXT    NOT NULL,
                timestamp       TEXT    NOT NULL,
                encrypted       INTEGER NOT NULL,
                tamper_detected INTEGER NOT NULL DEFAULT 0
            )
        """)

        # IntegrityLog table — one-to-one with TransferSession
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS IntegrityLog (
                log_id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id      INTEGER NOT NULL,
                original_hash   TEXT    NOT NULL,
                recomputed_hash TEXT    NOT NULL,
                hashes_match    INTEGER NOT NULL,
                tamper_detected INTEGER NOT NULL,
                FOREIGN KEY (session_id) REFERENCES TransferSession(session_id)
            )
        """)

        self.conn.commit()
        print(f"[LOGGER] Database ready at: {DB_PATH}")

    def log_session(self, filename: str, file_size: int,
                    sender_host: str, receiver_host: str,
                    encrypted: bool, tamper_detected: bool) -> int:
        """
        Records a transfer session to the TransferSession table.

        Args:
            filename        : name of the transferred file
            file_size       : size in bytes
            sender_host     : IP address of the sender
            receiver_host   : IP address of the receiver
            encrypted       : True if AES-256 encryption was used
            tamper_detected : True if integrity check failed

        Returns:
            session_id : the auto-generated ID for this session
                         used to link the IntegrityLog record
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO TransferSession
                (filename, file_size, sender_host, receiver_host,
                 timestamp, encrypted, tamper_detected)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            filename,
            file_size,
            sender_host,
            receiver_host,
            timestamp,
            1 if encrypted else 0,
            1 if tamper_detected else 0
        ))
        self.conn.commit()

        session_id = cursor.lastrowid
        print(f"[LOGGER] Session logged. ID: {session_id} | "
              f"File: {filename} | "
              f"{'Encrypted' if encrypted else 'Plaintext'} | "
              f"{'⚠️ TAMPERED' if tamper_detected else '✅ Clean'}")
        return session_id

    def log_integrity(self, session_id: int, original_hash: str,
                      recomputed_hash: str, tamper_detected: bool):
        """
        Records the integrity verification outcome to the IntegrityLog table.

        Args:
            session_id      : links this log to a TransferSession record
            original_hash   : SHA-256 hash computed by sender before encryption
            recomputed_hash : SHA-256 hash computed by receiver after decryption
            tamper_detected : True if hashes did not match
        """
        hashes_match = original_hash == recomputed_hash

        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO IntegrityLog
                (session_id, original_hash, recomputed_hash,
                 hashes_match, tamper_detected)
            VALUES (?, ?, ?, ?, ?)
        """, (
            session_id,
            original_hash,
            recomputed_hash,
            1 if hashes_match else 0,
            1 if tamper_detected else 0
        ))
        self.conn.commit()

        print(f"[LOGGER] Integrity log saved for session {session_id}. "
              f"Hashes {'match ✅' if hashes_match else 'DO NOT match ❌'}")

    def get_recent_sessions(self, limit: int = 10) -> list:
        """
        Retrieves the most recent transfer sessions.
        Used by the GUI to display the audit log.

        Returns a list of dicts, most recent first.
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT
                ts.session_id,
                ts.filename,
                ts.file_size,
                ts.sender_host,
                ts.receiver_host,
                ts.timestamp,
                ts.encrypted,
                ts.tamper_detected,
                il.original_hash,
                il.recomputed_hash,
                il.hashes_match
            FROM TransferSession ts
            LEFT JOIN IntegrityLog il
                ON ts.session_id = il.session_id
            ORDER BY ts.session_id DESC
            LIMIT ?
        """, (limit,))

        rows = cursor.fetchall()
        sessions = []
        for row in rows:
            sessions.append({
                "session_id"      : row[0],
                "filename"        : row[1],
                "file_size"       : row[2],
                "sender_host"     : row[3],
                "receiver_host"   : row[4],
                "timestamp"       : row[5],
                "encrypted"       : bool(row[6]),
                "tamper_detected" : bool(row[7]),
                "original_hash"   : row[8],
                "recomputed_hash" : row[9],
                "hashes_match"    : bool(row[10]) if row[10] is not None else None
            })
        return sessions

    def close(self):
        """Closes the database connection."""
        self.conn.close()