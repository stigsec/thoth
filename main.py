from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from argon2.low_level import hash_secret_raw, Type
from typing import Optional, Tuple
import getpass
import sys
import os

MAGIC = b'THOTH-STIGS\x00'
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
FILENAME_LEN_SIZE = 2

def get_key(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    key = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=64_000,
        parallelism=4,
        hash_len=KEY_SIZE,
        type=Type.ID
    )
    return key, salt

def encrypt_file(file: str, password: str) -> None:
    output = file + '.thoth'
    with open(file, 'rb') as f:
        plaintext = f.read()

    filename = os.path.basename(file).encode('utf-8')
    filename_len = len(filename).to_bytes(FILENAME_LEN_SIZE, 'big')

    key, salt = get_key(password)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)

    aad = MAGIC + salt + nonce + filename_len + filename
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    with open(output, 'wb') as f:
        f.write(MAGIC)
        f.write(salt)
        f.write(nonce)
        f.write(filename_len)
        f.write(filename)
        f.write(ciphertext)

    os.remove(file)

def read_encrypted_header(file: str):
    with open(file, 'rb') as f:
        magic = f.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError
        salt = f.read(SALT_SIZE)
        nonce = f.read(NONCE_SIZE)
        filename_len_bytes = f.read(FILENAME_LEN_SIZE)
        filename_len = int.from_bytes(filename_len_bytes, 'big')
        filename_bytes = f.read(filename_len)
        ciphertext = f.read()
    return salt, nonce, filename_len_bytes, filename_bytes, ciphertext

def decrypt_file(file: str, password: str) -> None:
    salt, nonce, filename_len_bytes, filename_bytes, ciphertext = read_encrypted_header(file)

    key, _ = get_key(password, salt)
    aesgcm = AESGCM(key)

    aad = MAGIC + salt + nonce + filename_len_bytes + filename_bytes

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        print('Error: invalid password or corrupted file')
        sys.exit(1)

    output = os.path.basename(filename_bytes.decode('utf-8'))

    with open(output, 'wb') as f:
        f.write(plaintext)

    os.remove(file)

def is_encrypted(file: str) -> bool:
    try:
        with open(file, 'rb') as f:
            return f.read(len(MAGIC)) == MAGIC
    except Exception:
        return False

def usage():
    print('Usage:')
    print('python3 main.py file')

if __name__ == '__main__':
    if len(sys.argv) != 2:
        usage()
        sys.exit(1)

    file = sys.argv[1]

    if not os.path.isfile(file):
        print(f'Error: file "{file}" does not exist')
        sys.exit(1)

    try:
        if is_encrypted(file):
            salt, nonce, filename_len_bytes, filename_bytes, _ = read_encrypted_header(file)
            output = os.path.basename(filename_bytes.decode('utf-8'))

            if os.path.exists(output):
                choice = input(f'File "{output}" already exists. Overwrite? [y/N]: ').strip().lower()
                if choice != 'y':
                    print('Aborted')
                    sys.exit(1)

            password = getpass.getpass('Password: ')
            decrypt_file(file, password)
            print('Decryption complete')
        else:
            password = getpass.getpass('Password: ')
            encrypt_file(file, password)
            print('Encryption complete')
    except Exception:
        print('Error: operation failed')
        sys.exit(1)
