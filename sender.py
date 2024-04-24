import os
import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from tkinter import Tk, filedialog
from Crypto.Random import get_random_bytes

def generate_aes_key():
    return os.urandom(16)
def encrypt_aes_key(aes_key, receiver_public_key):
    cipher_rsa = PKCS1_OAEP.new(receiver_public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(plaintext)

    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(iv + ciphertext)

    return encrypted_file_path

def compute_hash(file_path):
    hasher = SHA256.new()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            hasher.update(chunk)
    print('hash is:',hasher.digest())
    return hasher.digest()

def sign_hash(hash_value, sender_private_key):
    # Hash the data using SHA-256
    hasher = SHA256.new(hash_value)
    # Sign the hash
    signature = pkcs1_15.new(sender_private_key).sign(hasher)
    #print(signature)
    return signature


def main():
    root = Tk()
    root.withdraw()  # Hide the main window

    # Prompt the user to select a file
    file_path = filedialog.askopenfilename()
    if not file_path:
        print("No file selected. Exiting.")
        return
    print('file selected successfully')
    # Load sender's private key and receiver's public key
    sender_private_key = RSA.import_key(open('sender_private.pem').read())
    receiver_public_key = RSA.import_key(open('receiver_public.pem').read())

    # Generate AES key
    aes_key = generate_aes_key()
    # Encrypt file with AES
    encrypted_file_path = encrypt_file(file_path, aes_key)

    # Compute hash of the original file
    file_hash = compute_hash(file_path)

    # Sign the hash of the original file
    signature = sign_hash(file_hash, sender_private_key)

    # Encrypt the AES key with receiver's public key
    encrypted_aes_key = encrypt_aes_key(aes_key, receiver_public_key)
    #print(encrypted_aes_key)
    
    # Send the length of the encrypted AES key
    aes_key_length = len(encrypted_aes_key).to_bytes(4, byteorder='big')
    
    # Send encrypted file, encrypted AES key length, encrypted AES key, and digital signature to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 54321))
        s.sendall(aes_key_length)
        s.sendall(encrypted_aes_key)
        s.sendall(signature)
        with open(encrypted_file_path, 'rb') as f:
            s.sendfile(f)
    print('encrypted file,encrypted AES key and digital signature sent')
if __name__ == "__main__":
    main()
