import base64
from pathlib import Path

VERSION = b"v1"  


def package(iv: bytes, salt: bytes, ciphertext: bytes) -> str:
    """Pack version + iv + salt + ciphertext into Base64 string."""
    blob = VERSION + iv + salt + ciphertext
    return base64.b64encode(blob).decode("utf-8")


def unpack(blob: str) -> tuple[bytes, bytes, bytes, bytes]:
    """Unpack Base64 string into (version, iv, salt, ciphertext)."""
    raw = base64.b64decode(blob.encode("utf-8"))
    version, iv, salt, ciphertext = raw[:2], raw[2:14], raw[14:30], raw[30:]
    return version, iv, salt, ciphertext


def save_file(path: str, data: bytes):
    Path(path).write_bytes(data)


def load_file(path: str) -> bytes:
    return Path(path).read_bytes()
