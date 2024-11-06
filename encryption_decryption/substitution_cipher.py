# substitution_cipher.py

import string

def create_substitution_key(key):
    alphabet = string.ascii_lowercase
    shifted_alphabet = key + ''.join(sorted(set(alphabet) - set(key)))
    return str.maketrans(alphabet, shifted_alphabet), str.maketrans(shifted_alphabet, alphabet)

def substitution_encrypt(message, key):
    encrypt_key, _ = create_substitution_key(key)
    return message.translate(encrypt_key)

def substitution_decrypt(encrypted_message, key):
    _, decrypt_key = create_substitution_key(key)
    return encrypted_message.translate(decrypt_key)
