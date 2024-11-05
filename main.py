# main.py
from crypto_utils import generate_key
from password_manager import add_credential, get_credential
from password_generator import generate_password

def main():
    print("Welcome to CryptoPocket_Py!")

    # Generate or load encryption key
    key = generate_key()

    while True:
        print("\nOptions:")
        print("1. Store a credential")
        print("2. Retrieve a credential")
        print("3. Generate a random password")
        print("4. Exit")
        
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
            print("Exiting CryptoPocket_Py.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == '__main__':
    main()
