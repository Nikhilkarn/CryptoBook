# xor_cipher.py

def xor_encrypt(message, key):
    encrypted = ''.join(chr(ord(c) ^ key) for c in message)
    return encrypted

def xor_decrypt(encrypted_message, key):
    return xor_encrypt(encrypted_message, key)  # XOR encryption is reversible with the same key
