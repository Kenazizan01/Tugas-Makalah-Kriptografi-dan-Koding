from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from functionList import *
import time
import os


def sign_ecdsa_file(filename):
    keys_dir = "./keys/"   
    
    filename_ori = get_base_file_name(filename) 

    with open (filename, "rb") as file:
        message = file.read().strip()

    with open(os.path.join(keys_dir, "private_key_ecdsa.priv"), "rb") as priv_key_file:
        priv_key_data = priv_key_file.read()
        private_key = serialization.load_pem_private_key(priv_key_data, password=None, backend=default_backend())

    start_time = time.time()
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    end_time = time.time()

    with open(f'{filename_ori}_signature_ecdsa.txt', "w") as signature_file:
        signature_file.write(signature.hex())
        
    signing_time = end_time - start_time
    signature_size_bytes = len(signature)
    
    
    print('Signature succesfully saved into: ',f'{filename_ori}_signature_ecdsa.txt' )
    print("Signing Time:", signing_time, "seconds")
    print("Signature Size:", signature_size_bytes, "bytes")
    
def sign_eddsa_file(filename):
    keys_dir = "./keys/"   
    
    filename_ori = get_base_file_name(filename) 

    with open(filename, "rb") as file:
        message = file.read()

    with open(os.path.join(keys_dir, "private_key_eddsa.priv"), "rb") as priv_key_file:
        priv_key_data = priv_key_file.read()
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_key_data)

    start_time = time.time()
    signature = private_key.sign(message)
    end_time = time.time()

    with open(f'{filename_ori}_signature_eddsa.txt', "wb") as signature_file:
        signature_file.write(signature)

    signing_time = end_time - start_time
    signature_size_bytes = len(signature)

    print('Signature successfully saved into: ', f'{filename_ori}_signature_eddsa.txt')
    print("Signing Time:", signing_time, "seconds")
    print("Signature Size:", signature_size_bytes, "bytes")
    
    

    
filename = "18221107 - Ken Azizan - Report.pdf"
filename_ori = get_base_file_name(filename)
sign_ecdsa_file(filename)
sign_eddsa_file(filename)




"""
try:
    public_key.verify(signature,b'halo',ec.ECDSA(hashes.SHA256()))
    print("Verifikasi tanda tangan berhasil: Valid")
except:
    print("Verifikasi tanda tangan gagal: Tidak valid")
"""