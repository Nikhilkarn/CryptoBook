from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def generate_key():
    """Generates a new AES key for encryption/decryption."""
    return os.urandom(32)  

def encrypt_message(key, message):
    """Encrypts a text message with AES-GCM using the provided key."""
    iv = os.urandom(12)  
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return ciphertext, iv, encryptor.tag

def decrypt_message(key, ciphertext, iv, tag):
    """Decrypts a message encrypted with AES-GCM using the provided key."""
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_message.decode()
