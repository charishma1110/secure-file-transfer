from Crypto.PublicKey import RSA

# Generate RSA key pair with a key length of 2048 bits
receiver_key = RSA.generate(2048)

# Get the public and private keys
receiver_public_key = receiver_key.publickey().export_key()
receiver_private_key = receiver_key.export_key()

# Save the keys to files (optional)
with open('receiver_public.pem', 'wb') as f:
    f.write(receiver_public_key)

with open('receiver_private.pem', 'wb') as f:
    f.write(receiver_private_key)


print('\nReceiver RSA keys generated and saved to files.\n')
# Generate RSA key pair with a key length of 2048 bits
sender_key = RSA.generate(2048)

# Get the public and private keys
sender_public_key = sender_key.publickey().export_key()
sender_private_key = sender_key.export_key()

# Save the keys to files (optional)
with open('sender_public.pem', 'wb') as f:
    f.write(sender_public_key)

with open('sender_private.pem', 'wb') as f:
    f.write(sender_private_key)

print('\nSender RSA keys generated and saved to files.\n')
