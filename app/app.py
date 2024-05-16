import tkinter as tk
from tkinter import messagebox
from rsa_utils import generate_keypair, encrypt_rsa, decrypt_rsa
from database_utils import store_user, retrieve_user
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class RSA_AES_App:
    def __init__(self, root):
        self.root = root
        self.root.title("Sign Up and Sign In")
        self.create_widgets()
    
    def create_widgets(self):
        # Sign Up Section
        self.signup_frame = tk.LabelFrame(self.root, text="Sign Up", padx=10, pady=10)
        self.signup_frame.pack(padx=10, pady=10, fill="both", expand=True)
        
        tk.Label(self.signup_frame, text="Username:").grid(row=0, column=0, sticky="e")
        self.signup_username = tk.Entry(self.signup_frame, width=50)
        self.signup_username.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(self.signup_frame, text="Password:").grid(row=1, column=0, sticky="e")
        self.signup_password = tk.Entry(self.signup_frame, width=50, show='*')
        self.signup_password.grid(row=1, column=1, padx=5, pady=5)
        
        tk.Button(self.signup_frame, text="Sign Up", command=self.signup).grid(row=2, column=0, columnspan=2, pady=5)
        
        # Sign In Section
        self.signin_frame = tk.LabelFrame(self.root, text="Sign In", padx=10, pady=10)
        self.signin_frame.pack(padx=10, pady=10, fill="both", expand=True)
        
        tk.Label(self.signin_frame, text="Username:").grid(row=0, column=0, sticky="e")
        self.signin_username = tk.Entry(self.signin_frame, width=50)
        self.signin_username.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(self.signin_frame, text="Password:").grid(row=1, column=0, sticky="e")
        self.signin_password = tk.Entry(self.signin_frame, width=50, show='*')
        self.signin_password.grid(row=1, column=1, padx=5, pady=5)
        
        tk.Button(self.signin_frame, text="Sign In", command=self.signin).grid(row=2, column=0, columnspan=2, pady=5)

    def signup(self):
        username = self.signup_username.get()
        password = self.signup_password.get()
        
        # Generate RSA key pair
        public_key, private_key = generate_keypair()
        
        # Encrypt password using RSA public key
        encrypted_password = encrypt_rsa(public_key, password)
        
        # Store user data including public key
        store_user(username, encrypted_password, public_key)
        
        # Save private key components to environment variables
        os.environ['PRIVATE_KEY_D'] = str(private_key[0])  # private_key[0] is d
        os.environ['PRIVATE_KEY_N'] = str(private_key[1])  # private_key[1] is n
        
        # Append private key components to .env file
        with open('.env', 'a') as env_file:
            env_file.write(f"\nPRIVATE_KEY_D={private_key[0]}\n")
            env_file.write(f"PRIVATE_KEY_N={private_key[1]}\n")
        
        messagebox.showinfo("Success", "User signed up successfully!")
        self.signup_username.delete(0, tk.END)
        self.signup_password.delete(0, tk.END)
    
    def signin(self):
        username = self.signin_username.get()
        password = self.signin_password.get()
        
        # Retrieve encrypted password and public key from database
        encrypted_password, public_key = retrieve_user(username)
        
        if encrypted_password is None or public_key is None:
            messagebox.showerror("Error", "User not found or data incomplete!")
            return
        
        # Retrieve private key for the user from environment variables or secure storage
        private_key_d = int(os.getenv('PRIVATE_KEY_D', -1))
        private_key_n = int(os.getenv('PRIVATE_KEY_N', -1))
        
        if private_key_d == -1 or private_key_n == -1:
            messagebox.showerror("Error", "Private key not found!")
            return
        
        # Decrypt the encrypted password using RSA private key (d, n)
        private_key = (private_key_d, private_key_n)
        decrypted_password = decrypt_rsa(private_key, int(encrypted_password))
        
        if password == decrypted_password:
            messagebox.showinfo("Success", "User signed in successfully!")
        else:
            messagebox.showerror("Error", "Incorrect password!")
        
        self.signin_username.delete(0, tk.END)
        self.signin_password.delete(0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = RSA_AES_App(root)
    root.mainloop()
