from Crypto.Cipher import AES
import os

def derive_key(password: str, salt: bytes) -> bytes:
    """Derivar uma chave a partir da senha e do sal usando scrypt."""
    from Crypto.Protocol.KDF import scrypt
    return scrypt(password.encode(), salt, 32, N=16384, r=8, p=1)

def decrypt_file(file_path: str, key: bytes) -> None:
    """Descriptografar um arquivo usando a chave AES fornecida."""
    with open(file_path, 'rb') as file:
        nonce = file.read(16)
        tag = file.read(16)
        cipher_text = file.read()
    
    # Initialize cipher for decryption
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(cipher_text, tag)
    
    # Remove padding
    padding_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding_length]
    
    with open(file_path, 'wb') as file:
        file.write(decrypted_data)

def decrypt_directory(directory: str, password: str) -> None:
    """Descriptografar todos os arquivos em um diretório usando a senha fornecida."""
    with open('salt.bin', 'rb') as salt_file:
        salt = salt_file.read()
    key = derive_key(password, salt)
    
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            decrypt_file(file_path, key)

if __name__ == "__main__":
    directory = '/sdcard/Secret'
    password = 'passwd'
    decrypt_directory(directory, password)
    print("Descriptografia concluída.")
