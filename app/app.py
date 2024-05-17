import tkinter as tk
from tkinter import messagebox
from rsa_utils import generate_keypair, encrypt_rsa, decrypt_rsa
from rsa_utils import encrypt_aes_key_with_rsa, decrypt_aes_key_with_rsa
from aes_utils import encrypt_aes, decrypt_aes, generate_aes_key
from database_utils import store_user, retrieve_user, retrieve_additional_data
import os
from dotenv import load_dotenv
import base64

# Load environment variables from .env file
load_dotenv()

test_private_key = ""

class RSA_AES_App:
    global test_private_key

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
        
        tk.Button(self.signup_frame, text="Sign Up", command=self.signup).grid(row=5, column=0, columnspan=2, pady=5)
        
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
        global test_private_key
        username = self.signup_username.get()
        password = self.signup_password.get()
        name = self.signup_name.get()
        surname = self.signup_surname.get()
        address = self.signup_address.get()
        
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
        
        # # Generate RSA key pair
        public_key_encrypt_aes, private_key_encrypt_aes = generate_keypair()

        test_private_key = private_key_encrypt_aes
        print("THIS IS FIRST:", private_key_encrypt_aes)

        print(private_key_encrypt_aes)

        # # Encrypt AES key with RSA public key
        encrypted_aes_key = encrypt_aes_key_with_rsa(public_key_encrypt_aes, aes_key)
        # encoded_encrypted_aes_key = base64.b64encode(encrypted_aes_key).decode('utf-8')
        store_user(username, encrypted_password, public_key, public_key_encrypt_aes, encrypted_name, encrypted_surname, encrypted_address, encrypted_aes_key)

        # Encode the AES key to store it securely
        # encoded_aes_key = base64.b64encode(aes_key).decode('utf-8')

        # Store user data including public key and encrypted additional data (OLD)
        # store_user(username, encrypted_password, public_key, encrypted_name, encrypted_surname, encrypted_address, encoded_aes_key)
        
        # Save private key components to environment variables
        os.environ['PRIVATE_KEY_D'] = str(private_key[0])  # private_key[0] is d
        os.environ['PRIVATE_KEY_N'] = str(private_key[1])  # private_key[1] is n

        os.environ['PRIVATE_KEY_D_FOR_AES'] = str(private_key_encrypt_aes[0])  # private_key[0] is d
        os.environ['PRIVATE_KEY_N_FOR_AES'] = str(private_key_encrypt_aes[1])  # private_key[1] is n
        
        # Append private key components to .env file
        with open('.env', 'a') as env_file:
            env_file.write(f"\nPRIVATE_KEY_D={private_key[0]}\n")
            env_file.write(f"PRIVATE_KEY_N={private_key[1]}\n")
            env_file.write(f"PRIVATE_KEY_D_FOR_AES={private_key_encrypt_aes[0]}\n")
            env_file.write(f"PRIVATE_KEY_N_FOR_AES={private_key_encrypt_aes[1]}\n")

        messagebox.showinfo("Success", "User signed up successfully!")
        self.signup_username.delete(0, tk.END)
        self.signup_password.delete(0, tk.END)
        self.signup_name.delete(0, tk.END)
        self.signup_surname.delete(0, tk.END)
        self.signup_address.delete(0, tk.END)
    
    def signin(self):
        global test_private_key
        username = self.signin_username.get()
        password = self.signin_password.get()
        
        # Retrieve encrypted password, public key, and AES key from database
        encrypted_password, public_key, encrypted_aes_key = retrieve_user(username)
        
        if encrypted_password is None or public_key is None or encrypted_aes_key is None:
            messagebox.showerror("Error", "User not found or data incomplete!")
            return
        
        private_key_d_for_aes = int(os.getenv('PRIVATE_KEY_D_FOR_AES', -1))
        private_key_n_for_aes = int(os.getenv('PRIVATE_KEY_N_FOR_AES', -1))

        # Check if private key components are retrieved correctly
        if private_key_d_for_aes != -1 and private_key_n_for_aes != -1:
            # Construct RSA private key for AES decryption
            private_key_for_aes = (private_key_d_for_aes, private_key_n_for_aes)

            # Verify if private_key_for_aes contains both d and n components
            if len(private_key_for_aes) == 2:
                print("Private key components for AES decryption:", private_key_for_aes)
                # Decrypt the AES key using the RSA private key
                decrypted_aes_key = decrypt_aes_key_with_rsa(private_key_for_aes, encrypted_aes_key)
            else:
                messagebox.showerror("Error", "Private key components for AES decryption are incomplete!")
                return
        else:
            messagebox.showerror("Error", "Private key for AES decryption not found!")
            return

        # Construct RSA private key for AES decryption
        # private_key_for_aes = (private_key_d_for_aes, private_key_n_for_aes)

        if test_private_key == private_key_for_aes:
            print("HOLAAAA")
        else:
            print("HOLY")
            print("THIS IS test:", test_private_key)
            print("THIS IS 2nd:", private_key_for_aes)

        # Decrypt the AES key using the RSA private key
        # decrypted_aes_key = decrypt_aes_key_with_rsa(private_key_for_aes, encrypted_aes_key)

        # Decode the AES key
        # aes_key = base64.b64decode(encoded_aes_key)
        
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
            encrypted_name, encrypted_surname, encrypted_address = retrieve_additional_data(username)

            # Unpack nonce, ciphertext, and tag
            nonce_name, ciphertext_name, tag_name = encrypted_name
            nonce_surname, ciphertext_surname, tag_surname = encrypted_surname
            nonce_address, ciphertext_address, tag_address = encrypted_address
            
            decoded_nonce_name = base64.b64decode(nonce_name)
            decoded_nonce_surname = base64.b64decode(nonce_surname)
            decoded_nonce_address = base64.b64decode(nonce_address)

            # Convert encoded ciphertext and tag to bytes
            ciphertext_bytes_name = base64.b64decode(ciphertext_name)
            tag_bytes_name = base64.b64decode(tag_name)
            ciphertext_bytes_surname = base64.b64decode(ciphertext_surname)
            tag_bytes_surname = base64.b64decode(tag_surname)
            ciphertext_bytes_address = base64.b64decode(ciphertext_address)
            tag_bytes_address = base64.b64decode(tag_address)

            # Decrypt data using AES
            name = decrypt_aes(decrypted_aes_key, decoded_nonce_name, ciphertext_bytes_name, tag_bytes_name)
            surname = decrypt_aes(decrypted_aes_key, decoded_nonce_surname, ciphertext_bytes_surname, tag_bytes_surname)
            address = decrypt_aes(decrypted_aes_key, decoded_nonce_address, ciphertext_bytes_address, tag_bytes_address)

            # Create a new window to display user data
            self.display_user_data_window(name, surname, address)

            messagebox.showinfo("Success", "User signed in successfully!")
        else:
            messagebox.showerror("Error", "Incorrect password!")

    def display_user_data_window(self, name, surname, address):
        # Create a new window
        user_data_window = tk.Toplevel(self.root)
        user_data_window.title("User Data")
        
        # Display user data in labels
        tk.Label(user_data_window, text="Name:").grid(row=0, column=0, sticky="e")
        tk.Label(user_data_window, text=name).grid(row=0, column=1, sticky="w")
        
        tk.Label(user_data_window, text="Surname:").grid(row=1, column=0, sticky="e")
        tk.Label(user_data_window, text=surname).grid(row=1, column=1, sticky="w")
        
        tk.Label(user_data_window, text="Address:").grid(row=2, column=0, sticky="e")
        tk.Label(user_data_window, text=address).grid(row=2, column=1, sticky="w")


if __name__ == "__main__":
    root = tk.Tk()
    app = RSA_AES_App(root)
    root.mainloop()
