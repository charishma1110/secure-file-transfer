import os
import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

def decrypt_aes_key(encrypted_aes_key, receiver_private_key):
    try:
        cipher_rsa = PKCS1_OAEP.new(receiver_private_key)
        decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        return decrypted_aes_key
    except ValueError as e:
        print("Error decrypting AES key:", e)
        print("Length of encrypted AES key:", len(encrypted_aes_key))
        return None

from Crypto.Cipher import AES

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        ciphertext = file.read()
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    plaintext = cipher.decrypt(ciphertext)
    output_file_path = file_path[:-4]
    with open(output_file_path, 'wb') as output_file:
        output_file.write(plaintext)
    return output_file_path


def verify_signature(signature, hash_value, sender_public_key):
    try:
        verifier = pkcs1_15.new(sender_public_key)
        verifier.verify(SHA256.new(hash_value), signature)
        return True
    except (ValueError, TypeError) as e:
        print("Error verifying signature:", e)
        return False

def compute_hash(file_path):
    hasher = SHA256.new()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            hasher.update(chunk)
    print('\nhash is:',hasher.digest())
    return hasher.digest()

def decrypt_signature(encrypted_signature, sender_public_key):
    try:
        verifier = pkcs1_15.new(sender_public_key)
        verifier.verify(SHA256.new(b"message"), encrypted_signature)
        return encrypted_signature
    except (ValueError, TypeError) as e:
        print("Error decrypting signature:", e)
        return None

def receive_from_gmailserver():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('localhost', 54322))  # Binding to localhost on port 54322
        server_socket.listen()
        print("Waiting for sender to connect...")
        conn, addr = server_socket.accept()
        with conn:
            print('Connected by', addr)
            # Receive encrypted AES key length and key itself from gmailserver
            aes_key_length_data = conn.recv(4)
            aes_key_length = int.from_bytes(aes_key_length_data, byteorder='big')
            encrypted_aes_key = conn.recv(aes_key_length)
            with open('received_encrypted_aes_key.bin', 'wb') as f:
                f.write(encrypted_aes_key)
            # Receive digital signature
            signature = conn.recv(1024)
            #print(signature)
            with open('received_digital_signature.bin', 'wb') as f:
                f.write(signature)
            # Receive encrypted file from gmailserver
            with open('received_encrypted_file.enc', 'wb') as f:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    f.write(data)
    print("\nReceived encrypted AES key, digital signature, and file from gmailserver.")

def main():
    receiver_private_key = RSA.import_key(open('receiver_private.pem').read())
    sender_public_key = RSA.import_key(open('sender_public.pem').read())
    # Receive encrypted file, encrypted AES key, and digital signature from sender
    receive_from_gmailserver()

    # Decrypt AES key
    with open('received_encrypted_aes_key.bin', 'rb') as f:
        encrypted_aes_key = f.read()
        aes_key = decrypt_aes_key(encrypted_aes_key, receiver_private_key)

    # Decrypt file
    decrypted_file_path = decrypt_file('received_encrypted_file.enc', aes_key)

    # Decrypt digital signature
    with open('received_digital_signature.bin', 'rb') as f:
        encrypted_signature = f.read()
    # Compute hash of the decrypted file 
    decrypted_file_hash = compute_hash(decrypted_file_path)
    # Verify digital signature
    if verify_signature(encrypted_signature, decrypted_file_hash, sender_public_key):
        print("\nDigital signature verified. File integrity and authenticity confirmed.")
        # Print the decrypted file
        with open(decrypted_file_path, 'rb') as f:
            print(f"\nDecrypted file content:\n{f.read().decode()}")
    else:
        print("\nDigital signature verification failed. The file may have been tampered with.")
if __name__ == "__main__":
    main()
