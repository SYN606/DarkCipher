import os
import argparse
from colorama import Fore, init
from key_derivation import derive_key
from aes_gcm import encrypt, decrypt

init(autoreset=True)

def main():
    parser = argparse.ArgumentParser(description=f"{Fore.GREEN}AES-256-GCM Encryption Tool{Fore.RESET}")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", action="store_true", help="Encrypt mode")
    group.add_argument("-d", "--decrypt", action="store_true", help="Decrypt mode")
    parser.add_argument("-t", "--text", type=str, required=True, help="Text to encrypt/decrypt")
    parser.add_argument("-k", "--key", type=str, required=True, help="Encryption key")
    
    args = parser.parse_args()
    salt = os.urandom(16)
    key = derive_key(args.key, salt)

    if args.encrypt:
        iv, ciphertext = encrypt(args.text, key)
        print(f"\n{Fore.CYAN}ENCRYPTION RESULTS:{Fore.RESET}")
        print(f"{Fore.YELLOW}IV (hex):{Fore.RESET} {iv.hex()}")
        print(f"{Fore.YELLOW}Salt (hex):{Fore.RESET} {salt.hex()}")
        print(f"{Fore.YELLOW}Ciphertext (hex):{Fore.RESET} {ciphertext.hex()}")
    
    elif args.decrypt:
        iv_hex = input(f"{Fore.YELLOW}Enter IV (hex):{Fore.RESET} ")
        salt_hex = input(f"{Fore.YELLOW}Enter Salt (hex):{Fore.RESET} ")
        iv = bytes.fromhex(iv_hex)
        salt = bytes.fromhex(salt_hex)
        key = derive_key(args.key, salt)
        plaintext = decrypt(iv, bytes.fromhex(args.text), key)
        print(f"\n{Fore.GREEN}DECRYPTED TEXT:{Fore.RESET} {plaintext}")

if __name__ == "__main__":
    main()
