# caesar_cipher.py

def caesar_encrypt(message, shift):
    encrypted = ""
    for char in message:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encrypted += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encrypted += char
    return encrypted

def caesar_decrypt(encrypted_message, shift):
    return caesar_encrypt(encrypted_message, -shift)
