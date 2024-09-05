from cryptography.fernet import Fernet
import os
import base64
import hashlib

def generate_key(password):
    # Deriva uma chave a partir da senha
    key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest()[:32])
    return key

def decrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(file_path, 'wb') as file:
        file.write(decrypted_data)

def decrypt_directory(directory, password):
    key = generate_key(password)
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path):
            decrypt_file(file_path, key)

# Substitua pelos valores apropriados
directory_to_decrypt = '/sdcard/Secret'
decryption_password = 'passwd'

decrypt_directory(directory_to_decrypt, decryption_password)
