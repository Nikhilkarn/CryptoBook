from crypto_utils import generate_key, encrypt_message, decrypt_message
from password_manager import add_credential, get_credential
from password_generator import generate_password
from file_encryptor import encrypt_file, decrypt_file

def main():
    print("Welcome to CryptoPocket_Py!")

    key = generate_key()

    while True:
        print("\nOptions:")
        print("1. Store a credential")
        print("2. Retrieve a credential")
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
            add_credential(service, username, password, key)
            print("Credential added successfully.")

        elif choice == '2':
            service = input("Service Name: ")
            result = get_credential(service, key)
            if result:
                username, password = result
                print(f"Username: {username}, Password: {password}")
            else:
                print("No credential found for this service.")

        elif choice == '3':
            length = int(input("Password length: "))
            print("Generated Password:", generate_password(length))

        elif choice == '4':
            message = input("Enter text to encrypt: ")
            encrypted_message = encrypt_message(key, message)
            print("Encrypted Text:", encrypted_message)

        elif choice == '5':
            encrypted_message = input("Enter encrypted text to decrypt: ")
            try:
                decrypted_message = decrypt_message(key, encrypted_message)
                print("Decrypted Text:", decrypted_message)
            except:
                print("Decryption failed. Incorrect key or invalid text.")

        elif choice == '6':
            file_path = input("Enter the file path to encrypt: ")
            encrypt_file(key, file_path)

        elif choice == '7':
            encrypted_file_path = input("Enter the encrypted file path to decrypt: ")
            decrypt_file(key, encrypted_file_path)

        elif choice == '8':
            print("Exiting CryptoPocket_Py.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == '__main__':
    main()
