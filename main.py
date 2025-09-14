import argparse
from getpass import getpass
from colorama import Fore, init
from functions.key_derivation import derive_key_pbkdf2, derive_key_scrypt, generate_salt
from functions.aes_gcm import encrypt, decrypt
from functions.utils import package, unpack, save_file, load_file

init(autoreset=True)


def main():
    parser = argparse.ArgumentParser(
        description=f"{Fore.GREEN}AES-256-GCM Encryption Tool{Fore.RESET}")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e",
                       "--encrypt",
                       action="store_true",
                       help="Encrypt mode")
    group.add_argument("-d",
                       "--decrypt",
                       action="store_true",
                       help="Decrypt mode")

    parser.add_argument("-t",
                        "--text",
                        type=str,
                        help="Plaintext or Base64 blob")
    parser.add_argument("-f",
                        "--file",
                        type=str,
                        help="File to encrypt/decrypt")
    parser.add_argument("-o",
                        "--output",
                        type=str,
                        help="Output file (for file mode)")
    parser.add_argument("--kdf",
                        choices=["pbkdf2", "scrypt"],
                        default="pbkdf2",
                        help="Key derivation function")
    parser.add_argument("-k",
                        "--key",
                        type=str,
                        help="Password (use getpass if omitted)")

    args = parser.parse_args()
    password = args.key or getpass(
        f"{Fore.YELLOW}Enter password:{Fore.RESET} ")

    if args.encrypt:
        salt = generate_salt()
        key = derive_key_pbkdf2(
            password, salt) if args.kdf == "pbkdf2" else derive_key_scrypt(
                password, salt)

        if args.file:
            data = load_file(args.file)
            iv, ciphertext = encrypt(data, key)
            blob = package(iv, salt, ciphertext).encode()
            output = args.output or args.file + ".enc"
            save_file(output, blob)
            print(f"{Fore.CYAN}File encrypted → {output}{Fore.RESET}")
        elif args.text:
            iv, ciphertext = encrypt(args.text.encode(), key)
            blob = package(iv, salt, ciphertext)
            print(f"{Fore.CYAN}Encrypted blob:{Fore.RESET} {blob}")

    elif args.decrypt:
        if args.file:
            blob = load_file(args.file).decode()
        elif args.text:
            blob = args.text
        else:
            print(
                f"{Fore.RED}Error: must supply --text or --file for decryption.{Fore.RESET}"
            )
            return

        version, iv, salt, ciphertext = unpack(blob)
        key = derive_key_pbkdf2(
            password, salt) if args.kdf == "pbkdf2" else derive_key_scrypt(
                password, salt)

        try:
            plaintext = decrypt(iv, ciphertext, key)
            if args.file:
                output = args.output or args.file.replace(".enc", ".dec")
                save_file(output, plaintext)
                print(f"{Fore.GREEN}File decrypted → {output}{Fore.RESET}")
            else:
                print(
                    f"{Fore.GREEN}Decrypted text:{Fore.RESET} {plaintext.decode()}"
                )
        except ValueError as e:
            print(f"{Fore.RED}[!] {e}{Fore.RESET}")


if __name__ == "__main__":
    main()
