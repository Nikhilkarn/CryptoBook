def xor_encrypt(message, key):
    # Ensure the key is a single character and get its ASCII value
    key_value = ord(key[0]) if isinstance(key, str) and len(key) > 0 else 0
    encrypted = ''.join(chr(ord(c) ^ key_value) for c in message)
    return encrypted

def xor_decrypt(encrypted_message, key):
    return xor_encrypt(encrypted_message, key)  # XOR encryption is reversible with the same key
