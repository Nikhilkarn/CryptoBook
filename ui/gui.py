# gui.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from crypto_utils import generate_key, encrypt_message, decrypt_message
from password_manager import add_credential, get_credential
from password_generator import generate_password
from file_encryptor import encrypt_file, decrypt_file 

key = generate_key()

class CryptoPocketApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CryptoPocket")
        
        notebook = ttk.Notebook(root)
        notebook.pack(expand=True, fill="both")
        
        self.create_credential_tab(notebook)
        self.create_text_encryption_tab(notebook)
        self.create_file_encryption_tab(notebook)
        
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

        ttk.Button(text_frame, text="Encrypt", command=self.encrypt_text).grid(row=2, column=0, pady=5)
        ttk.Button(text_frame, text="Decrypt", command=self.decrypt_text).grid(row=2, column=1, pady=5)
    
    def create_file_encryption_tab(self, notebook):
        file_frame = ttk.Frame(notebook)
        notebook.add(file_frame, text="Encrypt File")

        ttk.Button(file_frame, text="Choose File", command=self.select_file).grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(file_frame, text="Encrypt File", command=self.encrypt_file).grid(row=1, column=0, padx=5, pady=5)
        ttk.Button(file_frame, text="Decrypt File", command=self.decrypt_file).grid(row=1, column=1, padx=5, pady=5)

    def add_credential(self):
        service = self.service_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        if service and username and password:
            add_credential(service, username, password, key)
            messagebox.showinfo("Success", "Credential added successfully")
        else:
            messagebox.showerror("Error", "Please fill in all fields")

    def encrypt_text(self):
        message = self.text_entry.get("1.0", tk.END).strip()
        if message:
            encrypted_message = encrypt_message(key, message)
            self.text_entry.delete("1.0", tk.END)
            self.text_entry.insert(tk.END, encrypted_message)
        else:
            messagebox.showerror("Error", "Please enter text to encrypt")

    def decrypt_text(self):
        encrypted_message = self.text_entry.get("1.0", tk.END).strip()
        if encrypted_message:
            try:
                decrypted_message = decrypt_message(key, encrypted_message)
                self.text_entry.delete("1.0", tk.END)
                self.text_entry.insert(tk.END, decrypted_message)
            except:
                messagebox.showerror("Error", "Decryption failed. Incorrect key or invalid text.")

    def select_file(self):
        self.file_path = filedialog.askopenfilename()
        if not self.file_path:
            messagebox.showerror("Error", "No file selected")

    def encrypt_file(self):
        if hasattr(self, 'file_path') and self.file_path:
            encrypt_file(key, self.file_path)
            messagebox.showinfo("Success", "File encrypted successfully")

    def decrypt_file(self):
        if hasattr(self, 'file_path') and self.file_path:
            decrypt_file(key, self.file_path)
            messagebox.showinfo("Success", "File decrypted successfully")

if __name__ == '__main__':
    root = tk.Tk()
    app = CryptoPocketApp(root)
    root.mainloop()
