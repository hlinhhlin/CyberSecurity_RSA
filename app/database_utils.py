#database_utils.py
import json
import os
import base64 

DATABASE_FILE = 'user_data.json'

def load_database():
    if not os.path.exists(DATABASE_FILE):
        return {'users': {}}
    with open(DATABASE_FILE, 'r') as file:
        return json.load(file)

def save_database(database):
    with open(DATABASE_FILE, 'w') as file:
        json.dump(database, file)

import base64
import json
import os

DATABASE_FILE = 'database.json'

def load_database():
    if os.path.exists(DATABASE_FILE):
        with open(DATABASE_FILE, 'r') as file:
            return json.load(file)
    return {'users': {}}

def save_database(database):
    with open(DATABASE_FILE, 'w') as file:
        json.dump(database, file, indent=4)

def store_user(username, encrypted_password, public_key, public_key_encrypt_aes, encrypted_name, encrypted_surname, encrypted_address, encrypted_aes_key):
    database = load_database()
    database['users'][username] = {
        'password': encrypted_password,
        'public_key': public_key,
        'public_key_for_aes': public_key_encrypt_aes,
        'aes_key': encrypted_aes_key,  # Store the AES key
        'name': [base64.b64encode(part).decode('utf-8') for part in encrypted_name],  # Convert each part to base64 string
        'surname': [base64.b64encode(part).decode('utf-8') for part in encrypted_surname],
        'address': [base64.b64encode(part).decode('utf-8') for part in encrypted_address],
    }
    save_database(database)

def retrieve_user(username):
    database = load_database()
    user_data = database['users'].get(username)
    if user_data:
        return user_data.get('password'), user_data.get('public_key'), user_data.get('aes_key')
    return None, None, None  # Return None if user not found or missing data

def retrieve_additional_data(username):
    database = load_database()
    user_data = database['users'].get(username)
    if user_data:
        return user_data.get('name'), user_data.get('surname'), user_data.get('address')
    return None, None, None  # Return None if user not found or missing data


