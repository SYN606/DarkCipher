import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt(plaintext: str, key: bytes) -> tuple[bytes, bytes]:
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode(), None)
    return iv, ciphertext

def decrypt(iv: bytes, ciphertext: bytes, key: bytes) -> str:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None).decode()
