from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from functionList import *
import time
import os


def sign_ecdsa_file(filename, key_filename):
    keys_dir = "./keys/"   
    signatures_dir = "./signatures/"
    os.makedirs(signatures_dir, exist_ok=True)
    
    filename_ori = get_base_file_name(filename) 

    with open (filename, "rb") as file:
        message = file.read().strip()

    # Mendapatkan kunci privat
    key_path = os.path.join(keys_dir, f"{key_filename}_ecdsa.priv")
    with open(key_path, "rb") as priv_key_file:
        priv_key_data = priv_key_file.read()
        private_key = serialization.load_pem_private_key(priv_key_data, password=None, backend=default_backend())

    # Membuat tanda tangan 
    start_time = time.time()
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    end_time = time.time()

    # Menyimpan tanda tangan pada file
    with open(os.path.join(signatures_dir, f'{filename_ori}_signature_ecdsa.txt'), "w") as signature_file:
        signature_file.write(signature.hex())
        
    signing_time = end_time - start_time
    signature_size_bytes = len(signature)
    
    
    print('Signature succesfully saved into: ',f'{filename_ori}_signature_ecdsa.txt' )
    print("Signing Time:", signing_time, "seconds")
    print("Signature Size:", signature_size_bytes, "bytes")
    
def sign_eddsa_file(filename, key_filename):
    keys_dir = "./keys/"   
    signatures_dir = "./signatures/"
    os.makedirs(signatures_dir, exist_ok=True)
    
    filename_ori = get_base_file_name(filename) 
   
    with open(filename, "rb") as file:
        message = file.read()

    # Mendapat kunci privat
    key_path = os.path.join(keys_dir, f"{key_filename}_eddsa.priv")
    with open(key_path, "rb") as priv_key_file:
        priv_key_data = priv_key_file.read()
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_key_data)
        
    # Membuat tanda tangan 
    start_time = time.time()
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    hashed_message = digest.finalize()
    signature = private_key.sign( hashed_message)
    end_time = time.time()

    # Menyimpan file tanda tangan 
    signature_path = os.path.join(signatures_dir, f'{filename_ori}_signature_eddsa.txt')
    with open(signature_path, "w") as signature_file:
        signature_file.write(signature.hex())

    signing_time = end_time - start_time
    signature_size_bytes = len(signature)

    print('Signature successfully saved into: ', f'{filename_ori}_signature_eddsa.txt')
    print("Signing Time:", signing_time, "seconds")
    print("Signature Size:", signature_size_bytes, "bytes")
    
    

    
#filename = "file_besar.mp4"
#filename_ori = get_base_file_name(filename)
#sign_ecdsa_file(filename,'key1')
#sign_eddsa_file(filename,'key2')
