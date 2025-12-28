import argparse
import sys
from getpass import getpass
from colorama import Fore, init

from crypt_core.aes_gcm import encrypt, decrypt
from crypt_core.key_derivation import (
    derive_key_pbkdf2,
    derive_key_scrypt,
    generate_salt,
)
from crypt_core.utils import (
    package,
    unpack,
    save_file,
    load_file,
    KDF_PBKDF2,
    KDF_SCRYPT,
)

init(autoreset=True)


def derive_key(password: bytes, salt: bytes, kdf: int) -> bytes:
    if kdf == KDF_PBKDF2:
        return derive_key_pbkdf2(password, salt)
    elif kdf == KDF_SCRYPT:
        return derive_key_scrypt(password, salt)
    else:
        raise ValueError("Unsupported KDF")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=f"{Fore.GREEN}AES-256-GCM Encryption Tool{Fore.RESET}")

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("-e",
                      "--encrypt",
                      action="store_true",
                      help="Encrypt mode")
    mode.add_argument("-d",
                      "--decrypt",
                      action="store_true",
                      help="Decrypt mode")

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-t",
                             "--text",
                             type=str,
                             help="Plaintext or Base64 blob")
    input_group.add_argument("-f",
                             "--file",
                             type=str,
                             help="File to encrypt/decrypt")

    parser.add_argument("-o", "--output", type=str, help="Output file")
    parser.add_argument(
        "--kdf",
        choices=["pbkdf2", "scrypt"],
        default="pbkdf2",
        help="Key derivation function (encryption only)",
    )
    parser.add_argument("-k",
                        "--key",
                        type=str,
                        help="Password (unsafe, prefer prompt)")

    args = parser.parse_args()

    # ---- Password handling ----
    if args.key:
        password = args.key.encode()
    else:
        if args.encrypt:
            p1 = getpass(f"{Fore.YELLOW}Enter password:{Fore.RESET} ")
            p2 = getpass(f"{Fore.YELLOW}Confirm password:{Fore.RESET} ")
            if p1 != p2:
                print(f"{Fore.RED}Passwords do not match.{Fore.RESET}")
                sys.exit(1)
            password = p1.encode()
        else:
            password = getpass(
                f"{Fore.YELLOW}Enter password:{Fore.RESET} ").encode()

    # ---- ENCRYPT ----
    if args.encrypt:
        salt = generate_salt()

        kdf_id = KDF_PBKDF2 if args.kdf == "pbkdf2" else KDF_SCRYPT
        key = derive_key(password, salt, kdf_id)

        aad = b"v1" + bytes([kdf_id])  # bind metadata to ciphertext

        if args.file:
            plaintext = load_file(args.file)
            iv, ciphertext = encrypt(plaintext, key, aad)
            blob = package(iv, salt, ciphertext, kdf_id).encode()

            output = args.output or args.file + ".enc"
            save_file(output, blob)
            print(f"{Fore.CYAN}File encrypted → {output}{Fore.RESET}")

        else:
            iv, ciphertext = encrypt(args.text.encode(), key, aad)
            blob = package(iv, salt, ciphertext, kdf_id)
            print(f"{Fore.CYAN}Encrypted blob:{Fore.RESET}\n{blob}")

    # ---- DECRYPT ----
    else:
        if args.file:
            blob = load_file(args.file).decode()
        else:
            blob = args.text

        try:
            version, kdf_id, iv, salt, ciphertext = unpack(blob)
        except Exception:
            print(f"{Fore.RED}Invalid or corrupted blob.{Fore.RESET}")
            sys.exit(1)

        aad = b"v1" + bytes([kdf_id])
        key = derive_key(password, salt, kdf_id)

        try:
            plaintext = decrypt(iv, ciphertext, key, aad)
        except ValueError as e:
            print(f"{Fore.RED}[!] {e}{Fore.RESET}")
            sys.exit(1)

        if args.file:
            output = args.output or args.file.replace(".enc", ".dec")
            save_file(output, plaintext)
            print(f"{Fore.GREEN}File decrypted → {output}{Fore.RESET}")
        else:
            print(
                f"{Fore.GREEN}Decrypted text:{Fore.RESET}\n{plaintext.decode()}"
            )

    # Best-effort password wipe
    for i in range(len(password)):
        password = b"\x00"


if __name__ == "__main__":
    main()
