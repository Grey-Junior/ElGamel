from Crypto.PublicKey import ElGamal
from Crypto.Random import random
from Crypto.Util.number import GCD, bytes_to_long, long_to_bytes
import hashlib
from datetime import datetime
import os

def load_public_key(directory, filename):
    #Load the public key from a file in the specified directory #
    file_path = os.path.join(directory, filename)
    with open(file_path, 'r') as file:
        p, g, y = map(int, file.read().split(','))
    return ElGamal.construct((p, g, y))

def encrypt_file(file_path, public_key, password):
    # Encrypt the file using the public key and password #
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Compute hash for integrity check of the original file
    hash_before = hashlib.sha256(file_data).hexdigest()

    # Append hash and password to file data
    file_data_with_hash_and_password = file_data + hash_before.encode() + password.encode()

    p = int(public_key.p)  # Ensure p is an integer
    g = public_key.g
    y = public_key.y

    k = random.StrongRandom().randint(1, p - 1)
    while GCD(k, p - 1) != 1:
        k = random.StrongRandom().randint(1, p - 1)

    c1 = pow(g, k, p)
    c2 = (bytes_to_long(file_data_with_hash_and_password) * int(pow(y, k, p))) % p
    encrypted_data = long_to_bytes(c1) + long_to_bytes(c2)

    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_data)

    # Compute hash of the encrypted data
    hash_after = hashlib.sha256(encrypted_data).hexdigest()

    return encrypted_file_path, hash_before, hash_after


def get_file_metadata(file_path):
    # Extract metadata from the file #
    metadata = {}
    metadata['File Name'] = os.path.basename(file_path)
    metadata['Size'] = os.path.getsize(file_path)
    metadata['Creation Time'] = datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
    metadata['Last Modified'] = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
    return metadata

def log_encryption(file_path, hash_before, hash_after, metadata, log_file="encryption.log"):
    # Log the encryption details in a log file #
    with open(log_file, 'a') as log:
        log.write("-" * 105 + "\n")
        log_entry = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f") + ": Encrypted '" + file_path + "' " "\n"
        log_entry += "Hash Before: " + hash_before + " - "
        log_entry += "File Name: " + metadata['File Name'] + "\n"
        log_entry += "Size: " + str(metadata['Size']) + "\n"
        log_entry += "Creation Time: " + metadata['Creation Time'] + "\n"
        log_entry += "Last Modified: " + metadata['Last Modified'] + "\n"
        log_entry += "Hash After: " + hash_after + "\n"
        log.write(log_entry)
        log.write("-" * 105 + "\n")

def main():
    # Relative path to the 'Keys' directory
    keys_directory = "Keys"
    public_key_file = "elgamal_public_key.txt"
    public_key = load_public_key(keys_directory, public_key_file)

    file_path = input("Enter the path of the file to encrypt: ")
    password = input("Enter your password: ")

    encrypted_file_path, hash_before, hash_after = encrypt_file(file_path, public_key, password)
    metadata = get_file_metadata(file_path)
    log_encryption(file_path, hash_before, hash_after, metadata)

    # Delete the original file
    os.remove(file_path)

    print(f"File encrypted and saved as {encrypted_file_path}. Original file deleted. Details logged.")

if __name__ == "__main__":
    main()