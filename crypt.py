from cryptography.fernet import Fernet
import os
import base64
import hashlib

def generate_key(password):
    # Deriva uma chave a partir da senha
    key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest()[:32])
    return key

def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        data = file.read()
    encrypted_data = fernet.encrypt(data)
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)

def encrypt_directory(directory, password):
    key = generate_key(password)
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path):
            encrypt_file(file_path, key)

# Substitua pelos valores apropriados
directory_to_encrypt = '/sdcard/Secret'
encryption_password = 'passwd'

encrypt_directory(directory_to_encrypt, encryption_password)
