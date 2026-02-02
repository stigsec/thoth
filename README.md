# THOTH

**THOTH** is a lightweight Python tool for secure file encryption and decryption.

---

## Features

- **Automatic encryption/decryption**: The tool detects whether a file is encrypted and acts accordingly.
- **Strong key derivation**: Uses Argon2id to derive keys from passwords, resisting brute-force and GPU attacks.
- **Authenticated encryption**: Encrypts data using AES-256-GCM, providing confidentiality and integrity.
- **Self-describing encrypted files**: Encrypted files contain authenticated metadata, including the original filename.
- **Safe error handling**: Detects incorrect passwords, corrupted files, or invalid input without data loss.
- **Minimal and fast**: Simple CLI interface with few dependencies.

---

## Getting Started

### Dependencies

Ensure you have Python 3 installed along with the required libraries:

```bash
pip install cryptography argon2-cffi
```

---

### Installation

1. Clone the repository:

```bash
git clone https://github.com/stigsec/thoth.git
```

2. Navigate to the project directory:

```bash
cd thoth
```

---

## Usage

### Syntax

```bash
python3 main.py file
```

You will then be prompted to input a password.

### Examples

#### Encryption
```bash
python3 main.py test.txt
```

After inputting a password, a file 'test.txt.thoth' will be created and original 'test.txt' will be deleted.

#### Decryption
```bash
python3 main.py test.txt.thoth
```
After inputting a password, a file 'test.txt' will be created and encrypted 'test.txt.thoth' will be deleted.  
**NOTE**: Renaming the encrypted file does **not** affect decryption.

---

## How it works

1. **Key Derivation**: A cryptographic key is derived from the password using Argon2id with a random per-file salt.
2. **Encryption**: File contents are encrypted using AES-256-GCM.
3. **Authenticated Header**: The encrypted file includes authenticated metadata:
  - Magic identifier
  - Salt
  - Nonce
  - Original filename
  - Any modification to the header or ciphertext is detected during decryption.
4. **Integrity Protection**: Incorrect passwords or tampered files fail securely without producing corrupted output.

## Security Notes
- Passwords are requested via secure prompt (not visible in process lists).
- Files are only deleted after successful encryption or decryption.
- No insecure algorithms are used.
- No user-configurable cryptographic parameters that could weaken security.
- THOTH is designed for local file encryption and does not attempt to manage key storage or recovery.

---

## License
This project is licensed under the GNU General Public License v3.0. See the [LICENSE file](LICENSE) for more details.

---

Developed by [stigsec](https://github.com/stigsec).
