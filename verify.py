from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from functionList import *
import time
import os

def verify_ecdsa_signature(filename, signature_filename, key_filename):
    keys_dir = "./keys/"
    signatures_dir = "./signatures/"

    filename_ori = get_base_file_name(filename)
    with open(filename, "rb") as file:
        message = file.read().strip()

    # mendapatkan kunci publik
    key_path = os.path.join(keys_dir, f"{key_filename}_ecdsa.pub")
    with open(key_path, "rb") as pub_key_file:
        pub_key_data = pub_key_file.read()
        public_key = serialization.load_pem_public_key(pub_key_data, backend=default_backend())

    # Membaca file tanda tangan
    signature_path = os.path.join(signatures_dir,f"{signature_filename}_signature_ecdsa.txt")
    with open(signature_path, "r") as signature_file:
        signature_hex = signature_file.read().strip()
        signature = bytes.fromhex(signature_hex)

    # Verifikasi tanda tangan
    try:
        start_time = time.time()
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        end_time = time.time()
        verification_time = end_time - start_time
        print("Verification successful.")
        print("Verification Time:", verification_time, "seconds")
    except:
        print("Verification failed. Signature does not match the message.")
        
def verify_eddsa_signature(filename, signature_filename, key_filename):
    keys_dir = "./keys/"
    signatures_dir = "./signatures/"

    filename_ori = get_base_file_name(filename)
    with open(filename, "rb") as file:
        message = file.read()
        

    # Mendapatkan kunci publik
    key_path = os.path.join(keys_dir, f"{key_filename}_eddsa.pub")
    with open(key_path, "rb") as pub_key_file:
        pub_key_data = pub_key_file.read()
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_key_data)

    # Membaca file tanda tangan
    signature_path = os.path.join(signatures_dir,f"{signature_filename}_signature_eddsa.txt")
    with open(signature_path, "r") as signature_file:
        signature_hex = signature_file.read().strip()
        signature = bytes.fromhex(signature_hex)

    # Verifikasi tanda tangan
    try:
        start_time = time.time()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(message)
        hashed_message = digest.finalize()
        public_key.verify(signature, hashed_message)
        end_time = time.time()
        verification_time = end_time - start_time
        print("Verification successful.")
        print("Verification Time:", verification_time, "seconds")
    except:
        print("Verification failed. Signature does not match the message.")
        
        
