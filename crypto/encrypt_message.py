from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_message(key: bytes, message: str) -> (bytes, bytes, bytes):
    """Encrypts a message with AES-GCM using the provided key."""
    iv = os.urandom(12)  # AES-GCM requires a 12-byte IV
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return ciphertext, iv, encryptor.tag  # Tag is needed for decryption
