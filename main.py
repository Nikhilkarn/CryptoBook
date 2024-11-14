import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from encryption_decryption.caesar_cipher import caesar_encrypt, caesar_decrypt
from encryption_decryption.xor_cipher import xor_encrypt, xor_decrypt
from encryption_decryption.substitution_cipher import substitution_encrypt, substitution_decrypt
from encryption_decryption.file_encryptor import encrypt_file, decrypt_file
from password_manager import add_credential, verify_credential
from password_generator import generate_password

class CryptoPocketApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CryptoPocket - Your Secure Vault")
        self.root.geometry("900x700")
        self.root.resizable(False, False)

        # Create a Notebook widget for tabs
        notebook = ttk.Notebook(root)
        notebook.pack(expand=True, fill="both")

        # Create tabs
        self.create_password_tab(notebook)
        self.create_text_encryption_tab(notebook)
        self.create_file_encryption_tab(notebook)

    def create_password_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Password Manager")

        # Add widgets for password management
        ttk.Label(frame, text="Service Name:").grid(row=0, column=0, padx=10, pady=10)
        service_entry = ttk.Entry(frame, width=30)
        service_entry.grid(row=0, column=1, padx=10, pady=10)

        ttk.Label(frame, text="Username:").grid(row=1, column=0, padx=10, pady=10)
        username_entry = ttk.Entry(frame, width=30)
        username_entry.grid(row=1, column=1, padx=10, pady=10)

        ttk.Label(frame, text="Password:").grid(row=2, column=0, padx=10, pady=10)
        password_entry = ttk.Entry(frame, show="*", width=30)
        password_entry.grid(row=2, column=1, padx=10, pady=10)

        # Generate and save buttons
        generate_btn = ttk.Button(frame, text="Generate Password", command=lambda: self.generate_password(password_entry))
        generate_btn.grid(row=3, column=0, padx=10, pady=10)

        save_btn = ttk.Button(frame, text="Save Credential", command=lambda: self.save_credential(service_entry.get(), username_entry.get(), password_entry.get()))
        save_btn.grid(row=3, column=1, padx=10, pady=10)

        # Verification widgets
        verify_btn = ttk.Button(frame, text="Verify Credential", command=lambda: self.verify_credential(service_entry.get(), username_entry.get(), password_entry.get()))
        verify_btn.grid(row=4, columnspan=2, pady=10)

    def generate_password(self, entry):
        password = generate_password()
        entry.delete(0, tk.END)
        entry.insert(0, password)
        messagebox.showinfo("Generated Password", f"Password: {password}")

    def save_credential(self, service, username, password):
        if service and username and password:
            add_credential(service, username, password)
            messagebox.showinfo("Success", "Credential saved successfully!")
        else:
            messagebox.showwarning("Warning", "Please fill in all fields")

    def verify_credential(self, service, username, password):
        if service and username and password:
            verified = verify_credential(service, username, password)
            if verified:
                messagebox.showinfo("Success", "Credential verified successfully!")
            else:
                messagebox.showerror("Error", "Verification failed!")
        else:
            messagebox.showwarning("Warning", "Please fill in all fields")

    def create_text_encryption_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Text Encryption")

        # Widgets for text encryption
        ttk.Label(frame, text="Enter Text:").pack(pady=10)
        text_entry = tk.Text(frame, height=10, width=60)
        text_entry.pack(pady=10)

        ttk.Label(frame, text="Select Cipher:").pack(pady=10)
        cipher_combobox = ttk.Combobox(frame, values=["Caesar Cipher", "XOR Cipher", "Substitution Cipher"])
        cipher_combobox.pack(pady=10)

        encrypt_btn = ttk.Button(frame, text="Encrypt", command=lambda: self.encrypt_text(text_entry, cipher_combobox))
        encrypt_btn.pack(pady=10)

        decrypt_btn = ttk.Button(frame, text="Decrypt", command=lambda: self.decrypt_text(text_entry, cipher_combobox))
        decrypt_btn.pack(pady=10)

    def encrypt_text(self, text_widget, cipher_combobox):
        text = text_widget.get("1.0", tk.END).strip()
        cipher = cipher_combobox.get()
        if cipher == "Caesar Cipher":
            encrypted = caesar_encrypt(text, 3)  # Adjust shift as needed
        elif cipher == "XOR Cipher":
            encrypted = xor_encrypt(text, "key")  # We can replace "key" with any other actual key
        elif cipher == "Substitution Cipher":
            key = "anykey"  # We can replace "key" with any other actual key
            encrypted = substitution_encrypt(text, key)
        else:
            messagebox.showwarning("Warning", "Select a valid cipher")
            return
        text_widget.delete("1.0", tk.END)
        text_widget.insert(tk.END, encrypted)

    def decrypt_text(self, text_widget, cipher_combobox):
        text = text_widget.get("1.0", tk.END).strip()
        cipher = cipher_combobox.get()
        if cipher == "Caesar Cipher":
            decrypted = caesar_decrypt(text, 3)  # Adjust shift as needed
        elif cipher == "XOR Cipher":
            decrypted = xor_decrypt(text, "key")  # Replace "key" with the actual key
        elif cipher == "Substitution Cipher":
            key = "anykey"  # Ensure the same key is used for decryption
            decrypted = substitution_decrypt(text, key)
        else:
            messagebox.showwarning("Warning", "Select a valid cipher")
            return
        text_widget.delete("1.0", tk.END)
        text_widget.insert(tk.END, decrypted)

    def create_file_encryption_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="File Encryption")

        # File selection and encryption widgets
        file_label = ttk.Label(frame, text="No file selected")
        file_label.pack(pady=10)

        select_file_btn = ttk.Button(frame, text="Select File", command=lambda: self.select_file(file_label))
        select_file_btn.pack(pady=10)

        encrypt_file_btn = ttk.Button(frame, text="Encrypt File", command=self.encrypt_selected_file)
        encrypt_file_btn.pack(pady=10)

        decrypt_file_btn = ttk.Button(frame, text="Decrypt File", command=self.decrypt_selected_file)
        decrypt_file_btn.pack(pady=10)

    def select_file(self, file_label):
        file_path = filedialog.askopenfilename()
        self.selected_file = file_path
        if file_path:
            file_label.config(text=f"Selected: {file_path.split('/')[-1]}")

    def encrypt_selected_file(self):
        if hasattr(self, 'selected_file'):
            key = "yourencryptionkey"  # Replace with your actual encryption key
            encrypt_file(key, self.selected_file)
            messagebox.showinfo("Success", "File encrypted successfully!")
        else:
            messagebox.showwarning("Warning", "Please select a file first")

    def decrypt_selected_file(self):
        if hasattr(self, 'selected_file'):
            key = "yourencryptionkey"  # Ensure the same key is used for decryption
            decrypt_file(key, self.selected_file)
            messagebox.showinfo("Success", "File decrypted successfully!")
        else:
            messagebox.showwarning("Warning", "Please select a file first")

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoPocketApp(root)
    root.mainloop()
