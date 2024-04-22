# CodeAlpha Internship Task - 5


# Importing required libraries
import RPi.GPIO as GPIO
import SimpleMFRC522
from cryptography.fernet import Fernet

# This function generates and returns a new encryption key
def generate_encryption_key():
    return Fernet.generate_key()

# This function encrypts the data using the encryption key
def encrypt_data(data, encryption_key):
    fernet = Fernet(encryption_key)
    return fernet.encrypt(data.encode())

# This function decrypts the data using the encryption key
def decrypt_data(encrypted_data, encryption_key):
    fernet = Fernet(encryption_key)
    return fernet.decrypt(encrypted_data).decode()

# Setting up RFID reader
reader = SimpleMFRC522.SimpleMFRC522()

try:
    # Generating a new encryption key for this session
    key = generate_encryption_key()
    
    # Prompt user for data to write to RFID tag
    text_to_write = input('Enter data to write to the RFID tag: ')
    encrypted_text = encrypt_data(text_to_write, key)
    
    print('Now place your tag to write.')
    reader.write(encrypted_text)
    print('Data written successfully.')
    
    print('Place your tag to read.')
    # Reading the data from the RFID tag
    id, encrypted_text_read = reader.read()
    decrypted_text = decrypt_data(encrypted_text_read, key)
    
    print(f'Decrypted data read from the tag: {decrypted_text}')
finally:
    # Cleaning up GPIO resources
    GPIO.cleanup()



