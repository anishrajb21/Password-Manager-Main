"""Best-effort session timeout and clipboard secret handling."""
from __future__ import annotations

import threading
import time


class SessionTimer:
    def __init__(self, timeout_seconds: int = 300):
        if not isinstance(timeout_seconds, int) or timeout_seconds < 30: raise ValueError("Timeout must be at least 30 seconds.")
        self.timeout_seconds = timeout_seconds
        self.last_activity = time.monotonic()
    def touch(self) -> None: self.last_activity = time.monotonic()
    def expired(self) -> bool: return time.monotonic() - self.last_activity >= self.timeout_seconds

_clipboard_timer = None

def copy_secret(secret: str, clear_after_seconds: int = 30) -> None:
    """Copy via pyperclip and clear only if clipboard still contains this exact secret."""
    global _clipboard_timer
    if not isinstance(clear_after_seconds, int) or not 5 <= clear_after_seconds <= 300: raise ValueError("Clipboard timeout must be between 5 and 300 seconds.")
    try:
        import pyperclip
    except ImportError as exc: raise RuntimeError("Clipboard support requires pyperclip; install requirements.txt.") from exc
    try: pyperclip.copy(secret)
    except Exception as exc: raise RuntimeError("Clipboard is unavailable on this system or in this session.") from exc
    if _clipboard_timer is not None: _clipboard_timer.cancel()
    def clear_if_unchanged():
        try:
            if pyperclip.paste() == secret: pyperclip.copy("")
        except (RuntimeError, OSError, ImportError) as exc:
            import logging
            logging.getLogger(__name__).debug("Clipboard cleanup failed: %s", exc)
    _clipboard_timer = threading.Timer(clear_after_seconds, clear_if_unchanged)
    _clipboard_timer.daemon = True; _clipboard_timer.start()
