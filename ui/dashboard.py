import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import threading
import queue
import argparse
import sys
import os

# Add project root to path so imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─────────────────────────────────────────────
#  Log Queue — background threads write here,
#  GUI reads and displays every 100ms
# ─────────────────────────────────────────────
log_queue = queue.Queue()


def queue_log(message: str, tag: str = "normal"):
    """
    Puts a log message into the queue for the GUI to display.
    Called from background threads — never touches tkinter directly.

    Tags control text colour:
        normal  — white
        success — green
        warning — orange
        error   — red
        info    — cyan
    """
    log_queue.put((message, tag))


def patch_print():
    """
    Redirects print() output from all modules into the log queue.
    This means every [SENDER], [RECEIVER], [ATTACKER] print statement
    automatically appears in the GUI without changing any existing code.
    """
    import builtins
    original_print = builtins.print

    def custom_print(*args, **kwargs):
        message = " ".join(str(a) for a in args)

        # Determine tag based on message content
        if any(x in message for x in ["✅", "ACK:OK", "intact", "saved"]):
            tag = "success"
        elif any(x in message for x in ["❌", "TAMPER", "FAILED", "rejected"]):
            tag = "error"
        elif any(x in message for x in ["⚠️", "PLAINTEXT", "WARNING"]):
            tag = "warning"
        elif any(x in message for x in ["[RSA]", "[AES]", "[INTEGRITY]",
                                         "[PAYLOAD]", "[ACK]"]):
            tag = "info"
        else:
            tag = "normal"

        log_queue.put((message, tag))
        original_print(*args, **kwargs)  # Still prints to terminal too

    builtins.print = custom_print


# ─────────────────────────────────────────────
#  Base Window — shared by all three roles
# ─────────────────────────────────────────────
class BaseWindow:
    """
    Base class for all three role windows.
    Provides the shared layout: header, log panel, status bar.
    Each role subclass adds its own controls above the log panel.
    """

    COLOURS = {
        "bg"        : "#1e1e2e",   # Dark background
        "panel"     : "#2a2a3e",   # Slightly lighter panel
        "accent"    : "#7c3aed",   # Purple accent
        "success"   : "#22c55e",   # Green
        "warning"   : "#f59e0b",   # Orange
        "error"     : "#ef4444",   # Red
        "info"      : "#38bdf8",   # Cyan
        "text"      : "#e2e8f0",   # Light text
        "subtext"   : "#94a3b8",   # Dimmed text
        "border"    : "#3f3f5a",   # Border colour
    }

    def __init__(self, root: tk.Tk, title: str, role: str):
        self.root = root
        self.role = role
        self.running = False

        # Window setup
        self.root.title(title)
        self.root.geometry("720x600")
        self.root.configure(bg=self.COLOURS["bg"])
        self.root.resizable(True, True)

        # Build layout
        self._build_header(title)
        self._build_controls()   # Role-specific — implemented by subclass
        self._build_log_panel()
        self._build_status_bar()

        # Start polling the log queue
        self.root.after(100, self._poll_log_queue)

    def _build_header(self, title: str):
        """Top banner showing role and title."""
        header_frame = tk.Frame(self.root, bg=self.COLOURS["accent"],
                                pady=12)
        header_frame.pack(fill=tk.X)

        tk.Label(
            header_frame,
            text=title,
            font=("Consolas", 16, "bold"),
            bg=self.COLOURS["accent"],
            fg="white"
        ).pack()

        tk.Label(
            header_frame,
            text="CNS Secure File Transfer — Proof of Concept",
            font=("Consolas", 9),
            bg=self.COLOURS["accent"],
            fg="#ddd6fe"
        ).pack()

    def _build_controls(self):
        """Override in subclass to add role-specific controls."""
        pass

    def _build_log_panel(self):
        """Scrollable log output area."""
        log_frame = tk.LabelFrame(
            self.root,
            text=" Activity Log ",
            font=("Consolas", 9, "bold"),
            bg=self.COLOURS["bg"],
            fg=self.COLOURS["subtext"],
            bd=1,
            relief=tk.SOLID,
            padx=8,
            pady=8
        )
        log_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(4, 4))

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            font=("Consolas", 9),
            bg="#0f0f1a",
            fg=self.COLOURS["text"],
            insertbackground="white",
            relief=tk.FLAT,
            state=tk.DISABLED,
            wrap=tk.WORD
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Colour tags for different message types
        self.log_text.tag_config("normal",  foreground=self.COLOURS["text"])
        self.log_text.tag_config("success", foreground=self.COLOURS["success"])
        self.log_text.tag_config("warning", foreground=self.COLOURS["warning"])
        self.log_text.tag_config("error",   foreground=self.COLOURS["error"])
        self.log_text.tag_config("info",    foreground=self.COLOURS["info"])

    def _build_status_bar(self):
        """Bottom status bar showing current state."""
        self.status_var = tk.StringVar(value="Ready")
        self.status_colour = tk.StringVar(value=self.COLOURS["subtext"])

        self.status_bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            font=("Consolas", 9),
            bg=self.COLOURS["panel"],
            fg=self.COLOURS["subtext"],
            anchor=tk.W,
            padx=12,
            pady=6
        )
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    def set_status(self, message: str, colour_key: str = "subtext"):
        """Updates the status bar from any thread safely via queue."""
        log_queue.put(("__STATUS__:" + message + "::" + colour_key, "status"))

    def _poll_log_queue(self):
        """
        Reads messages from the log queue and updates the GUI.
        Called every 100ms by tkinter's event loop.
        Never called from a background thread — always on main thread.
        """
        try:
            while True:
                message, tag = log_queue.get_nowait()

                if tag == "status":
                    # Parse status update
                    parts = message.replace("__STATUS__:", "").split("::")
                    status_text  = parts[0]
                    colour_key   = parts[1] if len(parts) > 1 else "subtext"
                    self.status_var.set(status_text)
                    self.status_bar.config(fg=self.COLOURS.get(
                                           colour_key, self.COLOURS["subtext"]))
                else:
                    # Append to log panel
                    self.log_text.config(state=tk.NORMAL)
                    self.log_text.insert(tk.END, message + "\n", tag)
                    self.log_text.see(tk.END)
                    self.log_text.config(state=tk.DISABLED)

        except queue.Empty:
            pass

        # Schedule next poll
        self.root.after(100, self._poll_log_queue)

    def _add_network_fields(self, parent, defaults: dict) -> dict:
        """
        Adds host/port input fields to a parent frame.
        Returns a dict of StringVar/IntVar for each field.

        defaults: {
            "host": "127.0.0.1",
            "port": 5002,
            ... (extra fields as needed)
        }
        """
        vars = {}
        col = 0
        for label, key, width in defaults:
            tk.Label(
                parent,
                text=label,
                font=("Consolas", 9),
                bg=self.COLOURS["panel"],
                fg=self.COLOURS["subtext"]
            ).grid(row=0, column=col, padx=(8, 2), pady=6)
            col += 1

            var = tk.StringVar(value=str(key))
            entry = tk.Entry(
                parent,
                textvariable=var,
                font=("Consolas", 9),
                bg=self.COLOURS["bg"],
                fg=self.COLOURS["text"],
                insertbackground="white",
                relief=tk.FLAT,
                width=width,
                bd=4
            )
            entry.grid(row=0, column=col, padx=(0, 12), pady=6)
            col += 1
            vars[label] = var

        return vars

    def _make_button(self, parent, text: str, command,
                     colour: str = None, width: int = 18) -> tk.Button:
        """Creates a styled button."""
        bg = colour or self.COLOURS["accent"]
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            font=("Consolas", 10, "bold"),
            bg=bg,
            fg="white",
            activebackground=self.COLOURS["border"],
            activeforeground="white",
            relief=tk.FLAT,
            cursor="hand2",
            width=width,
            pady=6
        )
        return btn


# ─────────────────────────────────────────────
#  Receiver Window
# ─────────────────────────────────────────────
class ReceiverWindow(BaseWindow):

    def __init__(self, root):
        super().__init__(root,
                         title="📥  RECEIVER NODE",
                         role="receiver")

    def _build_controls(self):
        controls = tk.Frame(self.root, bg=self.COLOURS["panel"], pady=4)
        controls.pack(fill=tk.X, padx=12, pady=(8, 4))

        # Network fields
        net_frame = tk.Frame(controls, bg=self.COLOURS["panel"])
        net_frame.pack(side=tk.LEFT)

        self.net_vars = self._add_network_fields(net_frame, [
            ("Listen Host:", "127.0.0.1", 14),
            ("Port:",        "5002",       6),
        ])

        # Start button
        btn_frame = tk.Frame(controls, bg=self.COLOURS["panel"])
        btn_frame.pack(side=tk.RIGHT, padx=8)

        self.start_btn = self._make_button(
            btn_frame, "▶  Start Receiver", self._start_receiver,
            colour="#16a34a"
        )
        self.start_btn.pack(side=tk.LEFT, padx=4)

        self._make_button(
            btn_frame, "🗑  Clear Log", self._clear_log,
            colour=self.COLOURS["border"], width=12
        ).pack(side=tk.LEFT, padx=4)

    def _start_receiver(self):
        if self.running:
            return

        host = self.net_vars["Listen Host:"].get()
        port = int(self.net_vars["Port:"].get())

        self.running = True
        self.start_btn.config(state=tk.DISABLED, text="⏳ Waiting...")
        self.set_status(f"Listening on {host}:{port}...", "info")

        def run():
            try:
                from network.receiver import start_receiver
                start_receiver(host=host, port=port)
                self.set_status("Transfer complete.", "success")
            except Exception as e:
                queue_log(f"[ERROR] {e}", "error")
                self.set_status(f"Error: {e}", "error")
            finally:
                self.running = False
                self.root.after(0, lambda: self.start_btn.config(
                    state=tk.NORMAL, text="▶  Start Receiver"))

        threading.Thread(target=run, daemon=True).start()

    def _clear_log(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)


# ─────────────────────────────────────────────
#  Attacker Window
# ─────────────────────────────────────────────
class AttackerWindow(BaseWindow):

    def __init__(self, root):
        super().__init__(root,
                         title="💀  ATTACKER NODE  (MITM)",
                         role="attacker")

    def _build_controls(self):
        controls = tk.Frame(self.root, bg=self.COLOURS["panel"], pady=4)
        controls.pack(fill=tk.X, padx=12, pady=(8, 4))

        # Network fields — two rows
        net_frame = tk.Frame(controls, bg=self.COLOURS["panel"])
        net_frame.pack(side=tk.LEFT)

        # Row 1 — listen address
        row1 = tk.Frame(net_frame, bg=self.COLOURS["panel"])
        row1.pack(anchor=tk.W)
        self.net_vars = self._add_network_fields(row1, [
            ("Listen Host:", "127.0.0.1", 14),
            ("Port:",        "5003",       6),
        ])

        # Row 2 — forward to receiver
        row2 = tk.Frame(net_frame, bg=self.COLOURS["panel"])
        row2.pack(anchor=tk.W)
        forward_vars = self._add_network_fields(row2, [
            ("Forward to:",  "127.0.0.1", 14),
            ("Port:",        "5002",       6),
        ])
        # Merge into net_vars with distinct keys
        self.net_vars["Forward to:"] = forward_vars["Forward to:"]
        self.net_vars["Fwd Port:"]   = forward_vars["Port:"]

        # Tamper toggle + buttons
        btn_frame = tk.Frame(controls, bg=self.COLOURS["panel"])
        btn_frame.pack(side=tk.RIGHT, padx=8)

        self.tamper_var = tk.BooleanVar(value=False)
        tamper_check = tk.Checkbutton(
            btn_frame,
            text="⚠️  Active Tamper",
            variable=self.tamper_var,
            font=("Consolas", 9, "bold"),
            bg=self.COLOURS["panel"],
            fg=self.COLOURS["warning"],
            selectcolor=self.COLOURS["bg"],
            activebackground=self.COLOURS["panel"],
            cursor="hand2"
        )
        tamper_check.pack(pady=(0, 4))

        self.start_btn = self._make_button(
            btn_frame, "▶  Start Attacker", self._start_attacker,
            colour="#dc2626"
        )
        self.start_btn.pack(padx=4)

    def _start_attacker(self):
        if self.running:
            return

        host         = self.net_vars["Listen Host:"].get()
        port         = int(self.net_vars["Port:"].get())
        fwd_host     = self.net_vars["Forward to:"].get()
        fwd_port     = int(self.net_vars["Fwd Port:"].get())
        tamper       = self.tamper_var.get()

        mode_text = "ACTIVE TAMPER" if tamper else "PASSIVE"
        self.running = True
        self.start_btn.config(state=tk.DISABLED, text="⏳ Waiting...")
        self.set_status(f"[{mode_text}] Listening on {host}:{port}...", "warning")

        def run():
            try:
                from network.attacker import start_attacker
                start_attacker(
                    tamper=tamper,
                    attacker_host=host,
                    attacker_port=port,
                    receiver_host=fwd_host,
                    receiver_port=fwd_port
                )
                self.set_status("Session complete.", "subtext")
            except Exception as e:
                queue_log(f"[ERROR] {e}", "error")
                self.set_status(f"Error: {e}", "error")
            finally:
                self.running = False
                self.root.after(0, lambda: self.start_btn.config(
                    state=tk.NORMAL, text="▶  Start Attacker"))

        threading.Thread(target=run, daemon=True).start()


# ─────────────────────────────────────────────
#  Sender Window
# ─────────────────────────────────────────────
class SenderWindow(BaseWindow):

    def __init__(self, root):
        super().__init__(root,
                         title="📤  SENDER NODE",
                         role="sender")

    def _build_controls(self):
        controls = tk.Frame(self.root, bg=self.COLOURS["panel"], pady=4)
        controls.pack(fill=tk.X, padx=12, pady=(8, 4))

        # Left side — file + network fields
        left = tk.Frame(controls, bg=self.COLOURS["panel"])
        left.pack(side=tk.LEFT)

        # Row 1 — file picker
        file_row = tk.Frame(left, bg=self.COLOURS["panel"])
        file_row.pack(anchor=tk.W, pady=(4, 0))

        tk.Label(
            file_row,
            text="File:",
            font=("Consolas", 9),
            bg=self.COLOURS["panel"],
            fg=self.COLOURS["subtext"]
        ).pack(side=tk.LEFT, padx=(8, 4))

        self.file_var = tk.StringVar(value="test_file.txt")
        tk.Entry(
            file_row,
            textvariable=self.file_var,
            font=("Consolas", 9),
            bg=self.COLOURS["bg"],
            fg=self.COLOURS["text"],
            insertbackground="white",
            relief=tk.FLAT,
            width=28,
            bd=4
        ).pack(side=tk.LEFT)

        self._make_button(
            file_row, "Browse", self._browse_file,
            colour=self.COLOURS["border"], width=8
        ).pack(side=tk.LEFT, padx=(4, 0))

        # Row 2 — network fields
        net_row = tk.Frame(left, bg=self.COLOURS["panel"])
        net_row.pack(anchor=tk.W)
        self.net_vars = self._add_network_fields(net_row, [
            ("Connect to:", "127.0.0.1", 14),
            ("Port:",       "5003",       6),
        ])

        # Right side — mode toggle + send button
        right = tk.Frame(controls, bg=self.COLOURS["panel"])
        right.pack(side=tk.RIGHT, padx=8)

        self.mode_var = tk.StringVar(value="encrypted")
        mode_frame = tk.Frame(right, bg=self.COLOURS["panel"])
        mode_frame.pack(pady=(4, 4))

        tk.Radiobutton(
            mode_frame, text="🔒 Encrypted",
            variable=self.mode_var, value="encrypted",
            font=("Consolas", 9, "bold"),
            bg=self.COLOURS["panel"],
            fg=self.COLOURS["success"],
            selectcolor=self.COLOURS["bg"],
            activebackground=self.COLOURS["panel"],
            cursor="hand2"
        ).pack(side=tk.LEFT, padx=4)

        tk.Radiobutton(
            mode_frame, text="⚠️  Plaintext",
            variable=self.mode_var, value="unencrypted",
            font=("Consolas", 9, "bold"),
            bg=self.COLOURS["panel"],
            fg=self.COLOURS["warning"],
            selectcolor=self.COLOURS["bg"],
            activebackground=self.COLOURS["panel"],
            cursor="hand2"
        ).pack(side=tk.LEFT, padx=4)

        self.send_btn = self._make_button(
            right, "📤  Send File", self._send_file,
            colour=self.COLOURS["accent"]
        )
        self.send_btn.pack(padx=4)

    def _browse_file(self):
        filepath = filedialog.askopenfilename(
            title="Select file to send",
            filetypes=[
                ("All files",       "*.*"),
                ("Text files",      "*.txt"),
                ("PDF files",       "*.pdf"),
                ("Image files",     "*.png *.jpg *.jpeg"),
            ]
        )
        if filepath:
            self.file_var.set(filepath)

    def _send_file(self):
        if self.running:
            return

        filepath  = self.file_var.get()
        host      = self.net_vars["Connect to:"].get()
        port      = int(self.net_vars["Port:"].get())
        encrypted = self.mode_var.get() == "encrypted"

        if not filepath:
            queue_log("[ERROR] No file selected.", "error")
            return

        mode_text = "ENCRYPTED" if encrypted else "PLAINTEXT"
        self.running = True
        self.send_btn.config(state=tk.DISABLED, text="⏳ Sending...")
        self.set_status(f"Sending [{mode_text}] → {host}:{port}", "info")

        def run():
            try:
                from network.sender import send_file
                send_file(filepath, encrypted=encrypted,
                          host=host, port=port)
                self.set_status("Transfer complete.", "success")
            except Exception as e:
                queue_log(f"[ERROR] {e}", "error")
                self.set_status(f"Error: {e}", "error")
            finally:
                self.running = False
                self.root.after(0, lambda: self.send_btn.config(
                    state=tk.NORMAL, text="📤  Send File"))

        threading.Thread(target=run, daemon=True).start()


# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="CNS Secure Transfer Dashboard")
    parser.add_argument(
        "--role",
        choices=["sender", "receiver", "attacker"],
        required=True,
        help="Which role window to open"
    )
    args = parser.parse_args()

    # Patch print before importing any network modules
    patch_print()

    root = tk.Tk()

    if args.role == "receiver":
        ReceiverWindow(root)
    elif args.role == "attacker":
        AttackerWindow(root)
    elif args.role == "sender":
        SenderWindow(root)

    root.mainloop()


if __name__ == "__main__":
    main()