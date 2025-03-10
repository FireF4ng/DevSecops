from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

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
    key = kdf.derive(password.encode())
    return key, salt

# AES encryption
def aes_encrypt(plaintext: str, key: bytes) -> str:
    """Encrypts plaintext using AES-256 in CBC mode."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad plaintext to a multiple of 16 bytes
    padding_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + chr(padding_length) * padding_length

    ciphertext = encryptor.update(padded_plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

# AES decryption
def aes_decrypt(ciphertext: str, key: bytes) -> str:
    """Decrypts AES-256 CBC encrypted text with padding validation."""
    try:
        raw_data = base64.b64decode(ciphertext)
        iv = raw_data[:16]
        encrypted_data = raw_data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Validate padding
        padding_length = decrypted_data[-1]
        if padding_length < 1 or padding_length > 16:
            raise ValueError("Invalid padding length")
        if decrypted_data[-padding_length:] != bytes([padding_length] * padding_length):
            raise ValueError("Invalid padding bytes")
        
        return decrypted_data[:-padding_length].decode()
    
    except (ValueError, IndexError, TypeError) as e:
        raise Exception(f"Decryption failed: {str(e)}")