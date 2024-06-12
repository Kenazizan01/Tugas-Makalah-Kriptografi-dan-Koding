from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import time
import os


def generate_key_ecdsa(filename):
    keys_dir = "./keys/"
    os.makedirs(keys_dir, exist_ok=True)

    # Pembangkitan pasangan kunci
    start_time = time.time()
    curve = ec.SECP256K1()
    private_key = ec.generate_private_key(curve, default_backend())
    public_key = private_key.public_key()
    end_time = time.time()
    

    # Penyimpanan kunci privat
    priv_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(os.path.join(keys_dir, f"{filename}_ecdsa.priv"), "wb") as priv_key_file:
        priv_key_file.write(priv_key_bytes)

    #Penyimpanan kunci publik
    pub_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(os.path.join(keys_dir, f"{filename}_ecdsa.pub"), "wb") as pub_key_file:
        pub_key_file.write(pub_key_bytes)
        
    generate_time = end_time - start_time
    print("Key Generation Time:", generate_time, "seconds")
    print("ECDSA Private Key saved to:", f"{filename}_ecdsa.priv")
    print("ECDSA Public Key saved to:", f"{filename}_ecdsa.pub")


def generate_key_eddsa(filename):
    keys_dir = "./keys/"
    os.makedirs(keys_dir, exist_ok=True)

    # Pembangkitan pasangan kunci
    start_time = time.time()
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()
    end_time = time.time()
    

    # Penyimpanan kunci privat
    priv_key_bytes = priv_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    with open(os.path.join(keys_dir, f"{filename}_eddsa.priv"), "wb") as privkey_file:
        privkey_file.write(priv_key_bytes)

    #Penyimpanan kunci publik
    pub_key_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    with open(os.path.join(keys_dir, f"{filename}_eddsa.pub"), "wb") as pubkey_file:
        pubkey_file.write(pub_key_bytes)

    generate_time = end_time - start_time
    print("Key Generation Time:",generate_time, "seconds")
    print("EdDSA Private Key saved to:", f"{filename}_eddsa.priv")
    print("EdDSA Public Key saved to:", f"{filename}_eddsa.pub")

#generate_key_ecdsa("key1")
#generate_key_eddsa("key2")

