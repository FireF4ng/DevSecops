from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os

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

# RSA Key Generation
def generate_rsa_keys() -> tuple:
    """Generates a RSA public/private key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# RSA Encryption
def rsa_encrypt(public_key, data: bytes) -> bytes:
    """Encrypt data using RSA public key."""
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# RSA Decryption
def rsa_decrypt(private_key, encrypted_data: bytes) -> bytes:
    """Decrypt data using RSA private key."""
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
