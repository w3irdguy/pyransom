from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import scrypt
import os

# Configurações
directory_to_decrypt = '/sdcard/Secret/'
password = 'youmoronxd'

# Ler o salt
def load_salt():
    with open('salt.bin', 'rb') as f:
        return f.read()

salt = load_salt()

# Derivar a chave AES256
key = scrypt(password.encode(), salt, 32, N=2**14, r=8, p=1)

# Função para descriptografar arquivos
def decrypt_file(file_path, cipher):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    with open(file_path[:-4], 'wb') as f:
        f.write(decrypted_data)

# Função para descriptografar um diretório
def decrypt_directory(directory):
    for foldername, subfolders, filenames in os.walk(directory):
        for filename in filenames:
            if filename.endswith('.enc'):
                file_path = os.path.join(foldername, filename)
                with open(file_path, 'rb') as f:
                    iv = f.read(AES.block_size)
                    encrypted_data = f.read()
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                decrypt_file(file_path, cipher)
                os.remove(file_path)

decrypt_directory(directory_to_decrypt)
