import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def encrypt(plaintext: bytes,
            key: bytes,
            aad: bytes | None = None) -> tuple[bytes, bytes]:
    """Encrypt bytes with AES-GCM. Returns (iv, ciphertext)."""
    iv = os.urandom(12)  # recommended nonce size
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, aad)
    return iv, ciphertext


def decrypt(iv: bytes,
            ciphertext: bytes,
            key: bytes,
            aad: bytes | None = None) -> bytes:
    """Decrypt AES-GCM ciphertext. Raises ValueError on failure."""
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(iv, ciphertext, aad)
    except InvalidTag:
        raise ValueError("Decryption failed: authentication tag mismatch.")
