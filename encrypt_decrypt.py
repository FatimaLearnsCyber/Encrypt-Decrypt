from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# Encrypt function using AES
def encrypt_message(plain_text, key):
    # Generate a random IV (Initialization Vector) for security
    iv = get_random_bytes(AES.block_size)
    
    # Create AES cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad the plain text to make sure it is a multiple of AES block size
    padded_plain_text = pad(plain_text.encode(), AES.block_size)
    
    # Encrypt the message
    cipher_text = cipher.encrypt(padded_plain_text)
    
    # Combine the IV and the cipher text
    encrypted_message = base64.b64encode(iv + cipher_text)
    
    return encrypted_message

# Decrypt function using AES
def decrypt_message(encrypted_message, key):
    # Decode the message from base64
    encrypted_message = base64.b64decode(encrypted_message)
    
    # Extract the IV (first 16 bytes) and cipher text (rest of the message)
    iv = encrypted_message[:AES.block_size]
    cipher_text = encrypted_message[AES.block_size:]
    
    # Create AES cipher object
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt the message
    decrypted_message = unpad(cipher.decrypt(cipher_text), AES.block_size).decode()
    
    return decrypted_message

# Get user input for encryption and decryption
def main():
    print("Welcome to the AES Encryption/Decryption Tool!")
    
    # Prompt user for a 16-byte key (128-bit key) and ensure it has correct length
    key_input = input("Enter a secret key (16 bytes long): ").encode()
    
    if len(key_input) != 16:
        print("The key must be 16 bytes long!")
        return
    
    print("\nSelect an option:")
    print("1. Encrypt a message")
    print("2. Decrypt a message")
    choice = input("Enter 1 or 2: ")

    if choice == "1":
        # Encrypt message
        plain_text = input("Enter a message to encrypt: ")
        encrypted_message = encrypt_message(plain_text, key_input)
        print("\nEncrypted message (Base64 encoded):")
        print(encrypted_message.decode())
    
    elif choice == "2":
        # Decrypt message
        encrypted_message = input("Enter the message to decrypt (Base64 encoded): ")
        decrypted_message = decrypt_message(encrypted_message, key_input)
        print("\nDecrypted message:")
        print(decrypted_message)
    else:
        print("Invalid choice! Please select either 1 or 2.")
    
if __name__ == "__main__":
    main()
