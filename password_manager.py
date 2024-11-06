import hashlib
import os
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

uri = "mongodb+srv://admin:admin13@crypto.vn67a.mongodb.net/?retryWrites=true&w=majority&appName=crypto"

client = MongoClient(uri, server_api=ServerApi('1'))

try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)

db = client["crypto"]
collection = db["credentials"]

def hash_password(password, salt=None):
    """Hashes a password using SHA-256 with a unique salt."""
    if not salt:
        salt = os.urandom(16)  
    hashed_password = hashlib.sha256(salt + password.encode()).hexdigest()
    return hashed_password, salt

def verify_password(stored_password, stored_salt, provided_password):
    """Verifies a password by hashing it with the stored salt and comparing it."""
    hashed_provided_password, _ = hash_password(provided_password, stored_salt)
    return hashed_provided_password == stored_password

def add_credential(service, username, password):
    """Adds a hashed credential to the database with a salt."""
    hashed_password, salt = hash_password(password)
    document = {
        "service": service,
        "username": username,
        "hashed_password": hashed_password,
        "salt": salt.hex()  
    }
    collection.insert_one(document)

def verify_credential(service, username, password):
    """Verifies a username and password against the stored hash for a given service."""
    result = collection.find_one({"service": service, "username": username})
    if result:
        stored_password = result["hashed_password"]
        stored_salt = bytes.fromhex(result["salt"])
        return verify_password(stored_password, stored_salt, password)
    return False
