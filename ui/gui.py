# gui.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from encryption_decryption.caesar_cipher import caesar_encrypt, caesar_decrypt
from encryption_decryption.xor_cipher import xor_encrypt, xor_decrypt
from encryption_decryption.substitution_cipher import substitution_encrypt, substitution_decrypt
from password_manager import add_credential, get_credential
from password_generator import generate_password

class CryptoPocketApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CryptoPocket")
        
        notebook = ttk.Notebook(root)
        notebook.pack(expand=True, fill="both")
        
        self.create_credential_tab(notebook)
        self.create_text_encryption_tab(notebook)
        
    def create_credential_tab(self, notebook):
        credential_frame = ttk.Frame(notebook)
        notebook.add(credential_frame, text="Store Credentials")
        
        ttk.Label(credential_frame, text="Service:").grid(row=0, column=0, padx=5, pady=5)
        self.service_entry = ttk.Entry(credential_frame)
        self.service_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(credential_frame, text="Username:").grid(row=1, column=0, padx=5, pady=5)
        self.username_entry = ttk.Entry(credential_frame)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(credential_frame, text="Password:").grid(row=2, column=0, padx=5, pady=5)
        self.password_entry = ttk.Entry(credential_frame)
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)

        ttk.Button(credential_frame, text="Add Credential", command=self.add_credential).grid(row=3, column=0, columnspan=2, pady=10)

    def create_text_encryption_tab(self, notebook):
        text_frame = ttk.Frame(notebook)
        notebook.add(text_frame, text="Encrypt Text")

        ttk.Label(text_frame, text="Text:").grid(row=0, column=0, padx=5, pady=5)
        self.text_entry = tk.Text(text_frame, width=40, height=10)
        self.text_entry.grid(row=1, column=0, padx=5, pady=5, columnspan=2)

        self.encryption_method = ttk.Combobox(text_frame, values=["Caesar Cipher", "XOR Cipher", "Substitution Cipher"])
        self.encryption_method.grid(row=2, column=0, padx=5, pady=5)
        self.encryption_method.set("Caesar Cipher")

        ttk.Button(text_frame, text="Encrypt", command=self.encrypt_text).grid(row=3, column=0, pady=5)
        ttk.Button(text_frame, text="Decrypt", command=self.decrypt_text).grid(row=3, column=1, pady=5)
    
    def add_credential(self):
        service = self.service_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        if service and username and password:
            add_credential(service, username, password)
            messagebox.showinfo("Success", "Credential added successfully")
        else:
            messagebox.showerror("Error", "Please fill in all fields")

    def encrypt_text(self):
        message = self.text_entry.get("1.0", tk.END).strip()
        method = self.encryption_method.get()
        
        if method == "Caesar Cipher":
            shift = 3  # Fixed shift value for demo
            encrypted_message = caesar_encrypt(message, shift)
        elif method == "XOR Cipher":
            key = 5  # Fixed key value for demo
            encrypted_message = xor_encrypt(message, key)
        elif method == "Substitution Cipher":
            key = 'keyword'  # Fixed keyword for demo
            encrypted_message = substitution_encrypt(message, key)
        
        self.text_entry.delete("1.0", tk.END)
        self.text_entry.insert(tk.END, encrypted_message)

    def decrypt_text(self):
        encrypted_message = self.text_entry.get("1.0", tk.END).strip()
        method = self.encryption_method.get()
        
        if method == "Caesar Cipher":
            shift = 3
            decrypted_message = caesar_decrypt(encrypted_message, shift)
        elif method == "XOR Cipher":
            key = 5
            decrypted_message = xor_decrypt(encrypted_message, key)
        elif method == "Substitution Cipher":
            key = 'keyword'
            decrypted_message = substitution_decrypt(encrypted_message, key)
        
        self.text_entry.delete("1.0", tk.END)
        self.text_entry.insert(tk.END, decrypted_message)

if __name__ == '__main__':
    root = tk.Tk()
    app = CryptoPocketApp(root)
    root.mainloop()
