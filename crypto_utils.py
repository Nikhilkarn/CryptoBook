from cryptography.fernet import Fernet

def generate_key():
    """Generates a new key for encryption/decryption."""
    return Fernet.generate_key()

def encrypt_message(key, message):
    """Encrypts a text message with the given key."""
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())

def decrypt_message(key, encrypted_message):
    """Decrypts an encrypted message with the given key."""
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()
