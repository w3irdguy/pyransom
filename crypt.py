from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def encrypt_file(file_path: str, cipher: AES) -> None:
    """Criptografar um arquivo usando o cifrador AES fornecido."""
    with open(file_path, 'rb') as file:
        file_data = file.read()
    
    # Pad the data to be a multiple of AES.block_size
    padding_length = AES.block_size - len(file_data) % AES.block_size
    padded_data = file_data + bytes([padding_length] * padding_length)
    
    cipher_text, tag = cipher.encrypt_and_digest(padded_data)
    
    with open(file_path, 'wb') as file:
        file.write(cipher.nonce + tag + cipher_text)

def encrypt_directory(directory: str, password: str) -> None:
    """Criptografar todos os arquivos em um diretório usando a senha fornecida."""
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_EAX)
    
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path, cipher)

    with open('salt.bin', 'wb') as salt_file:
        salt_file.write(salt)

def derive_key(password: str, salt: bytes) -> bytes:
    """Derivar uma chave a partir da senha e do sal usando scrypt."""
    from Crypto.Protocol.KDF import scrypt
    return scrypt(password.encode(), salt, 32, N=16384, r=8, p=1)

if __name__ == "__main__":
    directory = '/sdcard/Secret'
    password = 'passwd'
    encrypt_directory(directory, password)
    print("Criptografia concluída.")
