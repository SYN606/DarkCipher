import base64
from pathlib import Path

VERSION = 1
KDF_PBKDF2 = 1
KDF_SCRYPT = 2


def package(iv: bytes, salt: bytes, ciphertext: bytes, kdf: int) -> str:
    """Pack encrypted components into Base64 blob."""
    blob = (VERSION.to_bytes(1, "big") + kdf.to_bytes(1, "big") +
            len(iv).to_bytes(1, "big") + iv + len(salt).to_bytes(1, "big") +
            salt + ciphertext)
    return base64.b64encode(blob).decode("utf-8")


def unpack(blob: str) -> tuple[int, int, bytes, bytes, bytes]:
    """Unpack Base64 blob."""
    raw = base64.b64decode(blob.encode("utf-8"))

    version = raw[0]
    kdf = raw[1]

    iv_len = raw[2]
    offset = 3
    iv = raw[offset:offset + iv_len]
    offset += iv_len

    salt_len = raw[offset]
    offset += 1
    salt = raw[offset:offset + salt_len]
    offset += salt_len

    ciphertext = raw[offset:]
    return version, kdf, iv, salt, ciphertext


def save_file(path: str, data: bytes):
    Path(path).write_bytes(data)


def load_file(path: str) -> bytes:
    return Path(path).read_bytes()
