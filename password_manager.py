import sqlite3
from crypto_utils import encrypt_message, decrypt_message

DB_PATH = 'data/credentials.db'

def init_db():
    """Initializes the database for storing encrypted credentials."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT,
            username TEXT,
            encrypted_password BLOB
        )
    ''')
    conn.commit()
    conn.close()

def add_credential(service, username, password, key):
    """Adds an encrypted credential to the database."""
    encrypted_password = encrypt_message(key, password)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO credentials (service, username, encrypted_password) VALUES (?, ?, ?)',
              (service, username, encrypted_password))
    conn.commit()
    conn.close()

def get_credential(service, key):
    """Retrieves and decrypts the credential for a given service."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT username, encrypted_password FROM credentials WHERE service = ?', (service,))
    result = c.fetchone()
    conn.close()

    if result:
        username, encrypted_password = result
        password = decrypt_message(key, encrypted_password)
        return username, password
    return None
