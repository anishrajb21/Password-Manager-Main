"""Cryptographically secure password generation."""
import secrets
import string

DEFAULT_LENGTH = 16
MIN_LENGTH = 12
MAX_LENGTH = 128
SPECIALS = "!@#$%^&*()-_+=<>?"


def generate_password(length: int = DEFAULT_LENGTH) -> str:
    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("Password length must be an integer.")
    if not MIN_LENGTH <= length <= MAX_LENGTH:
        raise ValueError(f"Password length must be between {MIN_LENGTH} and {MAX_LENGTH}.")
    chars = string.ascii_letters + string.digits + SPECIALS
    return "".join(secrets.choice(chars) for _ in range(length))
