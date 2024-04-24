import socket

def receive_from_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('localhost', 54321))  # Binding to localhost on port 54321
        server_socket.listen()
        print("Waiting for sender to connect...")
        conn, addr = server_socket.accept()
        with conn:
            print('Connected by', addr)
            # Receive encrypted AES key length and key itself from sender
            aes_key_length_data = conn.recv(4)
            aes_key_length = int.from_bytes(aes_key_length_data, byteorder='big')
            encrypted_aes_key = conn.recv(aes_key_length)
            #print(encrypted_aes_key)
            with open('received_encrypted_aes_key.bin', 'wb') as f:
                f.write(encrypted_aes_key)
            # Receive digital signature
            signature = conn.recv(1024)
            with open('received_digital_signature.bin', 'wb') as f:
                f.write(signature)
            # Receive encrypted file from sender
            with open('received_encrypted_file.enc', 'wb') as f:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    f.write(data)
            print("Received encrypted AES key, digital signature, and file from sender.")
            with open('received_encrypted_file.enc', 'rb') as f:
                file_content = f.read()
                #print("Content of received file:", file_content)


def send_to_receiver():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(('localhost', 54322))  # Connect to localhost on port 54322 (receiver)
        # Send encrypted AES key length and key to receiver
        with open('received_encrypted_aes_key.bin', 'rb') as f:
            encrypted_aes_key = f.read()
            aes_key_length = len(encrypted_aes_key).to_bytes(4, byteorder='big')
            client_socket.sendall(aes_key_length)
            client_socket.sendall(encrypted_aes_key)
        # Send digital signature to receiver
        with open('received_digital_signature.bin', 'rb') as f:
            signature = f.read()
            client_socket.sendall(signature)
        # Send encrypted file to receiver
        with open('received_encrypted_file.enc', 'rb') as f:
            while True:
                data = f.read(1024)
                if not data:
                    break
                client_socket.sendall(data)
        print("Sent encrypted AES key, digital signature, and file to receiver.")

def main():
    receive_from_sender()
    send_to_receiver()

if __name__ == "__main__":
    main()
