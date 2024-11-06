from encryption_decryption.caesar_cipher import caesar_encrypt, caesar_decrypt
from encryption_decryption.xor_cipher import xor_encrypt, xor_decrypt
from encryption_decryption.substitution_cipher import substitution_encrypt, substitution_decrypt
from password_manager import add_credential, verify_credential
from password_generator import generate_password

def encrypt_file(method, key, file_path):
    with open(file_path, 'r') as f:
        content = f.read()
    
    if method == "caesar":
        encrypted_content = caesar_encrypt(content, key)
    elif method == "xor":
        encrypted_content = xor_encrypt(content, key)
    elif method == "substitution":
        encrypted_content = substitution_encrypt(content, key)
    
    with open(file_path + '.enc', 'w') as f:
        f.write(encrypted_content)
    
    print(f"File '{file_path}' encrypted successfully as '{file_path}.enc'")

def decrypt_file(method, key, encrypted_file_path):
    with open(encrypted_file_path, 'r') as f:
        encrypted_content = f.read()
    
    if method == "caesar":
        decrypted_content = caesar_decrypt(encrypted_content, key)
    elif method == "xor":
        decrypted_content = xor_decrypt(encrypted_content, key)
    elif method == "substitution":
        decrypted_content = substitution_decrypt(encrypted_content, key)
    
    original_file_path = encrypted_file_path.replace('.enc', '')
    with open(original_file_path, 'w') as f:
        f.write(decrypted_content)
    
    print(f"File '{encrypted_file_path}' decrypted successfully as '{original_file_path}'")

def main():
    print("Welcome to CryptoPocket_Py!")

    while True:
        print("\nOptions:")
        print("1. Store a credential")
        print("2. Verify a credential")
        print("3. Generate a random password")
        print("4. Encrypt text")
        print("5. Decrypt text")
        print("6. Encrypt file")
        print("7. Decrypt file")
        print("8. Exit")
        
        choice = input("Choose an option: ")

        if choice == '1':
            service = input("Service Name: ")
            username = input("Username: ")
            password = input("Password: ")
            add_credential(service, username, password)
            print("Credential added successfully.")

        elif choice == '2':
            service = input("Service Name: ")
            username = input("Username: ")
            password = input("Password: ")
            if verify_credential(service, username, password):
                print("Verification successful: Password is correct.")
            else:
                print("Verification failed: Incorrect password.")

        elif choice == '3':
            length = int(input("Password length: "))
            print("Generated Password:", generate_password(length))

        elif choice == '4':
            message = input("Enter text to encrypt: ")
            method = input("Choose encryption method (Caesar, XOR, Substitution): ").strip().lower()

            if method == "caesar":
                shift = int(input("Enter shift value: "))
                encrypted_message = caesar_encrypt(message, shift)
            elif method == "xor":
                key = int(input("Enter XOR key: "))
                encrypted_message = xor_encrypt(message, key)
            elif method == "substitution":
                key = input("Enter substitution key: ")
                encrypted_message = substitution_encrypt(message, key)
            else:
                print("Invalid encryption method.")
                continue

            print("Encrypted Text:", encrypted_message)

        elif choice == '5':
            encrypted_message = input("Enter encrypted text to decrypt: ")
            method = input("Choose decryption method (Caesar, XOR, Substitution): ").strip().lower()

            if method == "caesar":
                shift = int(input("Enter shift value: "))
                decrypted_message = caesar_decrypt(encrypted_message, shift)
            elif method == "xor":
                key = int(input("Enter XOR key: "))
                decrypted_message = xor_decrypt(encrypted_message, key)
            elif method == "substitution":
                key = input("Enter substitution key: ")
                decrypted_message = substitution_decrypt(encrypted_message, key)
            else:
                print("Invalid decryption method.")
                continue

            print("Decrypted Text:", decrypted_message)

        elif choice == '6':
            file_path = input("Enter the file path to encrypt: ")
            method = input("Choose encryption method (Caesar, XOR, Substitution): ").strip().lower()

            if method == "caesar":
                shift = int(input("Enter shift value: "))
                encrypt_file(method, shift, file_path)
            elif method == "xor":
                key = int(input("Enter XOR key: "))
                encrypt_file(method, key, file_path)
            elif method == "substitution":
                key = input("Enter substitution key: ")
                encrypt_file(method, key, file_path)
            else:
                print("Invalid encryption method.")
                continue

        elif choice == '7':
            encrypted_file_path = input("Enter the encrypted file path to decrypt: ")
            method = input("Choose decryption method (Caesar, XOR, Substitution): ").strip().lower()

            if method == "caesar":
                shift = int(input("Enter shift value: "))
                decrypt_file(method, shift, encrypted_file_path)
            elif method == "xor":
                key = int(input("Enter XOR key: "))
                decrypt_file(method, key, encrypted_file_path)
            elif method == "substitution":
                key = input("Enter substitution key: ")
                decrypt_file(method, key, encrypted_file_path)
            else:
                print("Invalid decryption method.")
                continue

        elif choice == '8':
            print("Exiting CryptoPocket_Py.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == '__main__':
    main()
