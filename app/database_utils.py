import json
import os

DATABASE_FILE = 'user_data.json'

def load_database():
    if not os.path.exists(DATABASE_FILE):
        return {'users': {}}
    with open(DATABASE_FILE, 'r') as file:
        return json.load(file)

def save_database(database):
    with open(DATABASE_FILE, 'w') as file:
        json.dump(database, file)

def store_user(username, encrypted_password, public_key):
    database = load_database()
    database['users'][username] = {
        'password': encrypted_password,
        'public_key': public_key
    }
    save_database(database)

def retrieve_user(username):
    database = load_database()
    user_data = database['users'].get(username)
    if user_data:
        return user_data.get('password'), user_data.get('public_key')
    return None, None  # Return None if user not found or missing data

