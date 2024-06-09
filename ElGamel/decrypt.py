import os
import hashlib
from Crypto.PublicKey import ElGamal
from Crypto.Util.number import long_to_bytes, bytes_to_long
from datetime import datetime

def determine_decrypted_file_path(file_path):
    # Determine the file path for the decrypted file #
    if file_path.endswith(".enc"):
        return file_path[:-4]  # Remove '.enc' from the file path
    else:
        return file_path + ".decrypted"  # Add '.decrypted' if no '.enc' extension

def load_private_key(directory, filename):
    # Load the private key from a file in the specified directory #
    file_path = os.path.join(directory, filename)
    with open(file_path, 'r') as file:
        p, g, x = map(int, file.read().split(','))
    return (p, g, x)

def decrypt_file(file_path, private_key_tuple, password):
    """ Decrypt the file using the private key and password """
    p, g, x = private_key_tuple
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    half_len = p.bit_length() // 8
    c1 = bytes_to_long(encrypted_data[:half_len])
    c2 = bytes_to_long(encrypted_data[half_len:])

    s = pow(c1, x, p)
    plaintext_with_hash_and_password = long_to_bytes((c2 * pow(s, p-2, p)) % p)

    # Assuming SHA-256 hash (64 hex characters)
    hash_length = 64
    password_length = len(password.encode())
    
    original_data = plaintext_with_hash_and_password[:-hash_length - password_length]
    embedded_hash = plaintext_with_hash_and_password[-hash_length - password_length:-password_length].decode()
    embedded_password = plaintext_with_hash_and_password[-password_length:].decode()

    if embedded_password != password:
        raise ValueError("Incorrect password")

    computed_hash = hashlib.sha256(original_data).hexdigest()
    if computed_hash != embedded_hash:
        raise ValueError("Data integrity check failed: The data has been altered or corrupted.")

    return original_data, embedded_hash

def log_decryption(file_path, hash_before, hash_after, log_file="decryption.log"):
    """ Log the decryption details in a log file """
    # ... [Log function content remains unchanged] ...
def get_file_metadata(file_path):
    """ Extract metadata from the file """
    metadata = {}
    metadata['File Name'] = os.path.basename(file_path)
    metadata['Size'] = os.path.getsize(file_path)
    metadata['Creation Time'] = datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
    metadata['Last Modified'] = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
    return metadata

def log_decryption(file_path, hash_before, hash_after, metadata, log_file="decryption.log"):
    """ Log the decryption details in a log file """
    with open(log_file, 'a') as log:
        log.write("-" * 105 + "\n")
        log_entry = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f") + ": Decrypted '" + file_path + "' " "\n"
        log_entry += "Hash Before: " + hash_before + " - "
        log_entry += "File Name: " + metadata['File Name'] + "\n"
        log_entry += "Size: " + str(metadata['Size']) + "\n"
        log_entry += "Creation Time: " + metadata['Creation Time'] + "\n"
        log_entry += "Last Modified: " + metadata['Last Modified'] + "\n"
        log_entry += "Hash After: " + hash_after + "\n"
        log.write(log_entry)
        log.write("-" * 105 + "\n")
        
def main():
    keys_directory = "Keys"
    private_key_file = "elgamal_private_key.txt"
    private_key = load_private_key(keys_directory, private_key_file)

    file_path = input("Enter the path of the file to decrypt: ")
    password = input("Enter your password: ")

    try:
        decrypted_data, original_hash = decrypt_file(file_path, private_key, password)
        decrypted_file_path = determine_decrypted_file_path(file_path)

        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)

        # Compute and display the hash of the decrypted file
        decrypted_hash = hashlib.sha256(decrypted_data).hexdigest()
        print(f"Hash of decrypted file: {decrypted_hash}")

        metadata = get_file_metadata(decrypted_file_path)
        log_decryption(file_path, original_hash, decrypted_hash, metadata)

        print(f"File decrypted successfully. Saved to {decrypted_file_path}")

        # Delete the original .enc file after successful decryption
        os.remove(file_path)
        print(f"Encrypted file {file_path} has been deleted.")

    except ValueError as e:
        print(e)

if __name__ == "__main__":
    main()


