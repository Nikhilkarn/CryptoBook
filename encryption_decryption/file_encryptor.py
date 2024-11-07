from crypto_utils import encrypt_message, decrypt_message

def encrypt_file(key, file_path):
    """Encrypts the contents of a file and saves it with a '.enc' extension."""
    with open(file_path, 'rb') as f:
        data = f.read()
    
    ciphertext, iv, tag = encrypt_message(key, data.decode('utf-8'))
    
    with open(file_path + '.enc', 'wb') as f:
        f.write(iv + tag + ciphertext)  

    print(f"File '{file_path}' encrypted successfully as '{file_path}.enc'")

def decrypt_file(key, encrypted_file_path):
    """Decrypts a '.enc' file and restores the original file."""
    with open(encrypted_file_path, 'rb') as f:
        iv = f.read(12)    
        tag = f.read(16)   
        ciphertext = f.read()  
    
    decrypted_data = decrypt_message(key, ciphertext, iv, tag)
    
    original_file_path = encrypted_file_path.replace('.enc', '')
    with open(original_file_path, 'w') as f:
        f.write(decrypted_data)
    
    print(f"File '{encrypted_file_path}' decrypted successfully as '{original_file_path}'")
