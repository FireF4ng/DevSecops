from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64
import random

# Diffie-Hellman parameters
P = 23  # Prime number
G = 5   # Generator

def generate_dh_keys():
    """Generates a private and public key for Diffie-Hellman."""
    private_key = random.randint(2, P - 2)
    public_key = pow(G, private_key, P)
    return private_key, public_key

def compute_shared_secret(private_key, received_public_key):
    """Computes the shared secret using Diffie-Hellman."""
    return pow(received_public_key, private_key, P)

# AES key generation
def derive_key(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Derives a 256-bit key from a password using PBKDF2."""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return key, salt

# PKCS7 padding
def pad(data: bytes) -> bytes:
    """Pads data to a multiple of 16 bytes using PKCS7."""
    padding_length = 16 - (len(data) % 16)
    return data + bytes([padding_length] * padding_length)

def unpad(data: bytes) -> bytes:
    """Removes PKCS7 padding and validates it."""
    padding_length = data[-1]
    if padding_length < 1 or padding_length > 16:
        raise ValueError("Invalid padding length")
    if data[-padding_length:] != bytes([padding_length] * padding_length):
        raise ValueError("Invalid padding bytes")
    return data[:-padding_length]

# AES encryption
def aes_encrypt(plaintext: str, key: bytes) -> str:
    """Encrypts plaintext using AES-256 in CBC mode with PKCS7 padding."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padded_plaintext = pad(plaintext.encode())
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

# AES decryption
def aes_decrypt(ciphertext: str, key: bytes) -> str:
    """Decrypts AES-256 CBC encrypted text and removes PKCS7 padding."""
    try:
        raw_data = base64.b64decode(ciphertext)
        iv = raw_data[:16]
        encrypted_data = raw_data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        return unpad(decrypted_data).decode()

    except (ValueError, IndexError, TypeError) as e:
        raise Exception(f"Decryption failed: {str(e)}")
