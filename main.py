from encryption_decryption.caesar_cipher import caesar_encrypt, caesar_decrypt
from encryption_decryption.xor_cipher import xor_encrypt, xor_decrypt
from encryption_decryption.substitution_cipher import substitution_encrypt, substitution_decrypt
from password_manager import add_credential, verify_credential
from password_generator import generate_password

def main():
    print("Welcome to CryptoPocket_Py!")

    while True:
        print("\nOptions:")
        print("1. Store a credential")
        print("2. Verify a credential")
        print("3. Generate a random password")
        print("4. Encrypt text")
        print("5. Decrypt text")
        print("6. Exit")
        
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
            print("Exiting CryptoPocket_Py.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == '__main__':
    main()
