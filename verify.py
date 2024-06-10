from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from functionList import *
import time
import os

def verify_ecdsa_signature(filename, signature_filename):
    keys_dir = "./keys/"

    filename_ori = get_base_file_name(filename)
    with open(filename, "rb") as file:
        message = file.read().strip()

    # Load the public key
    with open(os.path.join(keys_dir, "public_key_ecdsa.pub"), "rb") as pub_key_file:
        pub_key_data = pub_key_file.read()
        public_key = serialization.load_pem_public_key(pub_key_data, backend=default_backend())

    # Read the signature from the file
    with open(signature_filename, "r") as signature_file:
        signature_hex = signature_file.read().strip()
        signature = bytes.fromhex(signature_hex)

    # Verify the signature
    try:
        start_time = time.time()
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        end_time = time.time()
        verification_time = end_time - start_time
        print("Verification successful.")
        print("Verification Time:", verification_time, "seconds")
    except:
        print("Verification failed. Signature does not match the message.")
        
def verify_eddsa_signature(filename, signature_filename):
    keys_dir = "./keys/"

    filename_ori = get_base_file_name(filename)
    with open(filename, "rb") as file:
        message = file.read()

    # Load the public key
    with open(os.path.join(keys_dir, "public_key_eddsa.pub"), "rb") as pub_key_file:
        pub_key_data = pub_key_file.read()
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_key_data)

    # Read the signature from the file
    with open(signature_filename, "rb") as signature_file:
        signature = signature_file.read()

    # Verify the signature
    try:
        start_time = time.time()
        public_key.verify(signature, message)
        end_time = time.time()
        verification_time = end_time - start_time
        print("Verification successful.")
        print("Verification Time:", verification_time, "seconds")
    except:
        print("Verification failed. Signature does not match the message.")
        
        
filename = "18221107 - Ken Azizan - Report.pdf"
filename_ori = get_base_file_name(filename)
verify_ecdsa_signature(filename,f'{filename_ori}_signature_ecdsa.txt')
verify_eddsa_signature(filename,f'{filename_ori}_signature_eddsa.txt')