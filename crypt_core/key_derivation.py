import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def derive_key_pbkdf2(password: bytes,
                      salt: bytes,
                      iterations: int = 300_000) -> bytes:
    """Derive AES-256 key using PBKDF2-HMAC-SHA256."""
    if iterations < 100_000:
        raise ValueError("PBKDF2 iterations too low")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)


def derive_key_scrypt(password: bytes,
                      salt: bytes,
                      n: int = 2**14,
                      r: int = 8,
                      p: int = 1) -> bytes:
    """Derive AES-256 key using scrypt (memory-hard)."""
    if n < 2**14:
        raise ValueError("scrypt N parameter too low")

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=n,
        r=r,
        p=p,
    )
    return kdf.derive(password)


def generate_salt(size: int = 16) -> bytes:
    """Generate a cryptographically secure random salt."""
    return os.urandom(size)
