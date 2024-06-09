import os
from Crypto.Util.number import getPrime
from random import randint

def find_primitive_root(p):
    #Find a primitive root for a prime p 
    for g in range(2, p):
        if all(pow(g, (p - 1) // q, p) != 1 for q in [2, (p - 1) // 2]):
            return g
    return None

def generate_keys(bits=1024):
    #Generate private and public keys 
    p = getPrime(bits)
    g = find_primitive_root(p)
    private_key = randint(2, p - 2)
    public_key = pow(g, private_key, p)

    return p, g, private_key, public_key

def save_key(filename, data):
    #Save key data to a file 
    with open(filename, 'w') as file:
        file.write(','.join(map(str, data)))

def main():
    # Relative path to the 'Keys' directory
    keys_directory = "Keys"
    os.makedirs(keys_directory, exist_ok=True)

    p, g, private_key, public_key = generate_keys()

    # Save public key components to file
    public_key_file = os.path.join(keys_directory, "elgamal_public_key.txt")
    save_key(public_key_file, (p, g, public_key))

    # Save the private key to a separate file
    private_key_file = os.path.join(keys_directory, "elgamal_private_key.txt")
    save_key(private_key_file, (p, g, private_key))

    print("Keys generated and saved to the specified directory.")

if __name__ == "__main__":
    main()