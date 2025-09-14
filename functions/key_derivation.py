import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def derive_key_pbkdf2(password: str,
                      salt: bytes,
                      iterations: int = 300_000) -> bytes:
    """Derive AES-256 key using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def derive_key_scrypt(password: str,
                      salt: bytes,
                      n: int = 2**14,
                      r: int = 8,
                      p: int = 1) -> bytes:
    """Derive AES-256 key using scrypt (memory-hard)."""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=n,
        r=r,
        p=p,
    )
    return kdf.derive(password.encode("utf-8"))


def generate_salt(size: int = 16) -> bytes:
    """Generate a cryptographically secure random salt."""
    return os.urandom(size)
