# DarkCipher

[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-v1.0.0-purple.svg)](https://github.com/SYN606/DarkCipher/releases/tag/v1.0.0)
[![Issues](https://img.shields.io/github/issues/SYN606/DarkCipher.svg)](https://github.com/SYN606/DarkCipher/issues)
[![Stars](https://img.shields.io/github/stars/SYN606/DarkCipher.svg?style=social)](https://github.com/SYN606/DarkCipher/stargazers)
![Developer](https://img.shields.io/badge/developer-SYN-red.svg)

**DarkCipher** is a command-line tool for **AES-256-GCM encryption & decryption**, supporting both text and files.  
It derives encryption keys securely from passwords using **PBKDF2-HMAC-SHA256** (default) or **scrypt** (memory-hard).

---

## Features

- 🔐 **AES-256 in GCM mode** (authenticated encryption)
- 🧩 **Password-based key derivation** with PBKDF2 or scrypt
- 🎲 **Random salt (16 bytes) and IV (12 bytes)** per encryption
- 📦 **Unified Base64-encoded blob** (contains version, IV, salt, ciphertext)
- 📝 **Supports both text and files**
- 🙈 **Hidden password input** (via getpass)
- 🛠️ **Modular design** (`main.py`, `aes_gcm.py`, `key_derivation.py`, `utils.py`)
- ✅ **Includes pytest tests**

---

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/SYN606/DarkCipher.git
    cd DarkCipher
    ```

2. (Optional) Create and activate a virtual environment:

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use 'venv\Scripts\activate'
    ```

3. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

---

## Usage

**Encrypt a text or file:**

```python
python main.py encrypt --text "Secret Message"
python main.py encrypt --file secrets.txt
```

**Decrypt a text or file:**

```python
python main.py decrypt --text "<Base64Ciphertext>"
python main.py decrypt --file secrets.enc
```

- You will be prompted securely for a password.

---

## Contributing

Contributions, issues and feature requests are welcome!  
Please open an issue to discuss what you’d like to improve.

---

## Credits

- Inspired by cryptography best practices and secure password-based encryption
- Contributors: [SYN606](https://github.com/SYN606)

---
