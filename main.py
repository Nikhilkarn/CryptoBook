from password_manager import add_credential, verify_credential
from password_generator import generate_password

def main():
    print("Welcome to CryptoPocket_Py!")

    while True:
        print("\nOptions:")
        print("1. Store a credential")
        print("2. Verify a credential")
        print("3. Generate a random password")
        print("4. Exit")
        
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
            print("Exiting CryptoPocket_Py.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == '__main__':
    main()
