#app.py
import tkinter as tk
from tkinter import messagebox
from rsa_utils import generate_keypair, encrypt_rsa, decrypt_rsa
from aes_utils import encrypt_aes, decrypt_aes, generate_aes_key
from database_utils import store_user, retrieve_user, retrieve_additional_data
import os
from dotenv import load_dotenv
import base64

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
        
        tk.Label(self.signup_frame, text="Name:").grid(row=2, column=0, sticky="e")
        self.signup_name = tk.Entry(self.signup_frame, width=50)
        self.signup_name.grid(row=2, column=1, padx=5, pady=5)
        
        tk.Label(self.signup_frame, text="Surname:").grid(row=3, column=0, sticky="e")
        self.signup_surname = tk.Entry(self.signup_frame, width=50)
        self.signup_surname.grid(row=3, column=1, padx=5, pady=5)
        
        tk.Label(self.signup_frame, text="Address:").grid(row=4, column=0, sticky="e")
        self.signup_address = tk.Entry(self.signup_frame, width=50)
        self.signup_address.grid(row=4, column=1, padx=5, pady=5)
        
        tk.Label(self.signup_frame, text="Email:").grid(row=5, column=0, sticky="e")
        self.signup_email = tk.Entry(self.signup_frame, width=50)
        self.signup_email.grid(row=5, column=1, padx=5, pady=5)
        
        tk.Label(self.signup_frame, text="Telephone:").grid(row=6, column=0, sticky="e")
        self.signup_tel = tk.Entry(self.signup_frame, width=50)
        self.signup_tel.grid(row=6, column=1, padx=5, pady=5)
        
        tk.Button(self.signup_frame, text="Sign Up", command=self.signup).grid(row=7, column=0, columnspan=2, pady=5)
        
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
        name = self.signup_name.get()
        surname = self.signup_surname.get()
        address = self.signup_address.get()
        email = self.signup_email.get()
        tel = self.signup_tel.get()
        
        if not all([username, password, name, surname, address, email, tel]):
            messagebox.showwarning("Warning", "Please fill in all fields.")
            return
    
        # Generate RSA key pair
        public_key, private_key = generate_keypair()
        
        # Encrypt password using RSA public key
        encrypted_password = encrypt_rsa(public_key, password)

        # Generate AES key
        aes_key = generate_aes_key()
        
        # Encrypt additional user data using AES
        encrypted_name = encrypt_aes(aes_key, name)
        encrypted_surname = encrypt_aes(aes_key, surname)
        encrypted_address = encrypt_aes(aes_key, address)
        encrypted_email = encrypt_aes(aes_key, email)
        encrypted_tel = encrypt_aes(aes_key, tel)

        # Encode the AES key to store it securely
        encoded_aes_key = base64.b64encode(aes_key).decode('utf-8')

        # Store user data including public key and encrypted additional data
        store_user(username, encrypted_password, public_key, encrypted_name, encrypted_surname, encrypted_address, encrypted_email, encrypted_tel)
        
        # Save private key components to environment variables
        os.environ['PRIVATE_KEY_D'] = str(private_key[0])  # private_key[0] is d
        os.environ['PRIVATE_KEY_N'] = str(private_key[1])  # private_key[1] is n
        os.environ['AES_KEY'] = encoded_aes_key  # private_key[1] is n
        
        # Append private key components to .env file
        with open('.env', 'a') as env_file:
            env_file.write(f"\nPRIVATE_KEY_D={private_key[0]}\n")
            env_file.write(f"PRIVATE_KEY_N={private_key[1]}\n")
            env_file.write(f"AES_KEY={encoded_aes_key}\n")
        
        messagebox.showinfo("Success", "User signed up successfully!")
        self.signup_username.delete(0, tk.END)
        self.signup_password.delete(0, tk.END)
        self.signup_name.delete(0, tk.END)
        self.signup_surname.delete(0, tk.END)
        self.signup_address.delete(0, tk.END)
        self.signup_email.delete(0, tk.END)
        self.signup_tel.delete(0, tk.END)
        
    def signin(self):
        username = self.signin_username.get()
        password = self.signin_password.get()
        
        # Retrieve encrypted password, public key, and AES key from database
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
            # Retrieve additional user data
            encrypted_name, encrypted_surname, encrypted_address, encrypted_email, encrypted_tel = retrieve_additional_data(username)

            encoded_aes_key = os.getenv('AES_KEY', -1)

            if encoded_aes_key == -1:
                messagebox.showerror("Error", "AES key not found!")
                return

            # Decode the AES key
            aes_key = base64.b64decode(encoded_aes_key)
            
            # Unpack nonce, ciphertext, and tag
            nonce_name, ciphertext_name, tag_name = encrypted_name
            nonce_surname, ciphertext_surname, tag_surname = encrypted_surname
            nonce_address, ciphertext_address, tag_address = encrypted_address
            nonce_email, ciphertext_email, tag_email = encrypted_email
            nonce_tel, ciphertext_tel, tag_tel = encrypted_tel
            
            decoded_nonce_name = base64.b64decode(nonce_name)
            decoded_nonce_surname = base64.b64decode(nonce_surname)
            decoded_nonce_address = base64.b64decode(nonce_address)
            decoded_nonce_email = base64.b64decode(nonce_email)
            decoded_nonce_tel = base64.b64decode(nonce_tel)

            # Convert encoded ciphertext and tag to bytes
            ciphertext_bytes_name = base64.b64decode(ciphertext_name)
            tag_bytes_name = base64.b64decode(tag_name)
            ciphertext_bytes_surname = base64.b64decode(ciphertext_surname)
            tag_bytes_surname = base64.b64decode(tag_surname)
            ciphertext_bytes_address = base64.b64decode(ciphertext_address)
            tag_bytes_address = base64.b64decode(tag_address)
            ciphertext_bytes_email = base64.b64decode(ciphertext_email)
            tag_bytes_email = base64.b64decode(tag_email)
            ciphertext_bytes_tel = base64.b64decode(ciphertext_tel)
            tag_bytes_tel = base64.b64decode(tag_tel)

            # Decrypt data using AES
            name = decrypt_aes(aes_key, decoded_nonce_name, ciphertext_bytes_name, tag_bytes_name)
            surname = decrypt_aes(aes_key, decoded_nonce_surname, ciphertext_bytes_surname, tag_bytes_surname)
            address = decrypt_aes(aes_key, decoded_nonce_address, ciphertext_bytes_address, tag_bytes_address)
            email = decrypt_aes(aes_key, decoded_nonce_email, ciphertext_bytes_email, tag_bytes_email)
            tel = decrypt_aes(aes_key, decoded_nonce_tel, ciphertext_bytes_tel, tag_bytes_tel)

            # Create a new window to display user data
            self.display_user_data_window(name, surname, address, email, tel)

            messagebox.showinfo("Success", "User signed in successfully!")
        else:
            messagebox.showerror("Error", "Incorrect password!")

    def display_user_data_window(self, name, surname, address, email, tel):
        # Create a new window
        user_data_window = tk.Toplevel(self.root)
        user_data_window.title("User Data")
        
        # Set minimum size for the window
        user_data_window.minsize(400, 300)  # Adjust these values as needed
        
        # Create a larger font
        large_font = ('Helvetica', 16)
        
        # Set padding
        padding = 10
        
        # Display user data in labels with larger font and padding
        tk.Label(user_data_window, text="Name:", font=large_font).grid(row=0, column=0, sticky="e", padx=padding, pady=padding)
        tk.Label(user_data_window, text=name, font=large_font).grid(row=0, column=1, sticky="w", padx=padding, pady=padding)
        
        tk.Label(user_data_window, text="Surname:", font=large_font).grid(row=1, column=0, sticky="e", padx=padding, pady=padding)
        tk.Label(user_data_window, text=surname, font=large_font).grid(row=1, column=1, sticky="w", padx=padding, pady=padding)
        
        tk.Label(user_data_window, text="Address:", font=large_font).grid(row=2, column=0, sticky="e", padx=padding, pady=padding)
        tk.Label(user_data_window, text=address, font=large_font).grid(row=2, column=1, sticky="w", padx=padding, pady=padding)

        tk.Label(user_data_window, text="Email:", font=large_font).grid(row=3, column=0, sticky="e", padx=padding, pady=padding)
        tk.Label(user_data_window, text=email, font=large_font).grid(row=3, column=1, sticky="w", padx=padding, pady=padding)

        tk.Label(user_data_window, text="Telephone:", font=large_font).grid(row=4, column=0, sticky="e", padx=padding, pady=padding)
        tk.Label(user_data_window, text=tel, font=large_font).grid(row=4, column=1, sticky="w", padx=padding, pady=padding)

if __name__ == "__main__":
    root = tk.Tk()
    app = RSA_AES_App(root)
    root.mainloop()
