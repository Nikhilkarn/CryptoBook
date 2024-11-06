from crypto_utils import generate_key, encrypt_message, decrypt_message
from password_manager import add_credential, verify_credential
from password_generator import generate_password
from file_encryptor import encrypt_file, decrypt_file

encryption_key = generate_key()

def main():
    print("Welcome to CryptoPocket_Py!")

    while True:
        print("\nOptions:")
        print("1. Store a credential")
        print("2. Verify a credential")
        print("3. Generate a random password")
        print("4. Encrypt text")
        print("5. Decrypt text")
        print("6. Encrypt a file")
        print("7. Decrypt a file")
        print("8. Exit")
        
        choice = input("Choose an option: ")

        if choice == '1':
            service = input("Service Name: ")
            username = input("Username: ")
            password = input("Password: ")
            add_credential(service, username, password)
            print("Credential added and hashed successfully.")

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
            ciphertext, iv, tag = encrypt_message(encryption_key, message)
            print(f"Encrypted Text: {ciphertext}\nIV: {iv}\nTag: {tag}")

        elif choice == '5':
            ciphertext = input("Enter encrypted text to decrypt: ")
            iv = input("Enter IV: ")
            tag = input("Enter Tag: ")
            try:
                decrypted_message = decrypt_message(encryption_key, bytes.fromhex(ciphertext), bytes.fromhex(iv), bytes.fromhex(tag))
                print("Decrypted Text:", decrypted_message)
            except:
                print("Decryption failed. Incorrect key or invalid text.")

        elif choice == '6':
            file_path = input("Enter the file path to encrypt: ")
            encrypt_file(encryption_key, file_path)

        elif choice == '7':
            encrypted_file_path = input("Enter the encrypted file path to decrypt: ")
            decrypt_file(encryption_key, encrypted_file_path)

        elif choice == '8':
            print("Exiting CryptoPocket_Py.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == '__main__':
    main()
