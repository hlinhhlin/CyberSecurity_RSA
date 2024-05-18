import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from database_utils import save_database, load_database

def generate_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters.parameter_bytes(encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3).decode('utf-8')

def store_dh_parameters(username, dh_parameters):
    database = load_database()
    database['dh_parameters'][username] = dh_parameters
    save_database(database)

def retrieve_other_dh_public_key(username):
    database = load_database()
    return database['dh_parameters'].get(username)

def store_dh_public_key(username, dh_public_key_bytes):
    database = load_database()
    database['dh_public_keys'][username] = dh_public_key_bytes
    save_database(database)

def retrieve_other_dh_public_key(username):
    database = load_database()
    return database['dh_public_keys'].get(username)


