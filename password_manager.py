from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from crypto_utils import encrypt_message, decrypt_message

uri = "mongodb+srv://admin:admin13@crypto.vn67a.mongodb.net/?retryWrites=true&w=majority&appName=crypto"

# Create a new client and connect to the server
client = MongoClient(uri, server_api=ServerApi('1'))

# Send a ping to confirm a successful connection
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)

# Database and collection setup
db = client["crypto"]
collection = db["credentials"]

def add_credential(service, username, password, key):
    """Adds an encrypted credential to the database."""
    encrypted_password = encrypt_message(key, password)
    document = {
        "service": service,
        "username": username,
        "encrypted_password": encrypted_password
    }
    collection.insert_one(document)

def get_credential(service, key):
    """Retrieves and decrypts the credential for a given service."""
    result = collection.find_one({"service": service})

    if result:
        username = result["username"]
        encrypted_password = result["encrypted_password"]
        password = decrypt_message(key, encrypted_password)
        return username, password
    return None
