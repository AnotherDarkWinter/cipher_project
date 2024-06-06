import tkinter as tk
from tkinter import messagebox
from encryption import encryp_aes, encrypt_rsa, hash_sha256, generate_rsa_keys
from decryption import decrypt_aes, decrypt_rsa

class CipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption and Decryption")
        self.setup_ui()
        
    def setup_ui(self):
        self.message_label = tk.Label(self.root, text="Message:")
        self.message_label.grid(row=0, column=0, padx=10, pady=10)
        
        self.message_entry = tk.Entry(self.root, width=50)
        self.message_entry.grid(row=0, column=1, padx=10, pady=10)
        
        self.key_label = tk.Label(self.root, text="Key (for AES):")
        self.key_label.grid(row=1, column=0, padx=10, pady=10)
        
        self.key_entry = tk.Entry(self.root, width=50)
        self.key_entry.grid(row=1, column=1, padx=10, pady=10)
        
        self.encrypt_aes_button = tk.Button(self.root, text="Encrypt AES", command=self.encrypt_aes)
        self.encrypt_aes_button.grid(row=2, column=0, padx=10, pady=10)
        
        self.decrypt_aes_button = tk.Button(self.root, text="Decrypt AES", command=self.decrypt_aes)
        self.decrypt_aes_button.grid(row=2, column=1, padx=10, pady=10)
        
        self.encrypt_rsa_button = tk.Button(self.root, text="Encrypt RSA", command=self.encrypt_rsa)
        self.encrypt_rsa_button.grid(row=3, column=0, padx=10, pady=10)
        
        self.decrypt_rsa_button = tk.Button(self.root, text="Decrypt RSA", command=self.decrypt_rsa)
        self.decrypt_rsa_button.grid(row=3, column=1, padx=10, pady=10)
        
        self.hash_button = tk.Button(self.root, text="Hash SHA256", command=self.hash_sha256)
        self.hash_button.grid(row=4, column=0, padx=10, pady=10)
        
        self.output_label = tk.Label(self.root, text="Output:")
        self.output_label.grid(row=5, column=0, padx=10, pady=10)
        
        self.output_entry = tk.Entry(self.root, width=50)
        self.output_entry.grid(row=5, column=1, padx=10, pady=10)
    
    def encrypt_aes(self):
        message = self.message_entry.get()
        key = self.key_entry.get().encode('utf-8')
        if len(key) != 16:
            messagebox.showerror("Error", "Key must be 16 bytes long for AES.")
            return
        encrypted_message = encrypt_aes(message, key)
        self.output_entry.delete(0, tk.END)
        self.output_entry.insert(0, encrypted_message)
    
    def decrypt_aes(self):
        ciphertext = self.output_entry.get()
        key = self.key_entry.get().encode('utf-8')
        try:
            decrypted_message = decrypt_aes(ciphertext, key)
            self.message_entry.delete(0, tk.END)
            self.message_entry.insert(0, decrypted_message)
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def encrypt_rsa(self):
        message = self.message_entry.get()
        private_key, public_key = generate_rsa_keys()
        encrypted_message = encrypt_rsa(message, public_key)
        self.output_entry.delete(0, tk.END)
        self.output_entry.insert(0, encrypted_message)
    
    def decrypt_rsa(self):
        ciphertext = self.output_entry.get()
        private_key, public_key = generate_rsa_keys()  # Normally, you'd load an existing key pair
        try:
            decrypted_message = decrypt_rsa(ciphertext, private_key)
            self.message_entry.delete(0, tk.END)
            self.message_entry.insert(0, decrypted_message)
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def hash_sha256(self):
        message = self.message_entry.get()
        hashed_message = hash_sha256(message)
        self.output_entry.delete(0, tk.END)
        self.output_entry.insert(0, hashed_message)

if __name__ == "__main__":
    root = tk.Tk()
    app = CipherApp(root)
    root.mainloop()

        