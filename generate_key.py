from ecpy.curves import Curve
from ecpy.keys import ECPublicKey, ECPrivateKey
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import secrets
import os


def generate_key_ecdsa():
    keys_dir = "./keys/"
    os.makedirs(keys_dir, exist_ok=True)

    # Define the elliptic curve
    curve = ec.SECP256K1()

    # Generate a private key
    private_key = ec.generate_private_key(curve, default_backend())

    # Get the public key
    public_key = private_key.public_key()

    # Serialize and save the private key to file
    priv_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(os.path.join(keys_dir, "private_key_ecdsa.priv"), "wb") as priv_key_file:
        priv_key_file.write(priv_key_bytes)

    # Serialize and save the public key to file
    pub_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(os.path.join(keys_dir, "public_key_ecdsa.pub"), "wb") as pub_key_file:
        pub_key_file.write(pub_key_bytes)

    print("ECDSA Private Key saved to:", os.path.join(keys_dir, "private_key_ecdsa.priv"))
    print("ECDSA Public Key saved to:", os.path.join(keys_dir, "public_key_ecdsa.pub"))


def generate_key_eddsa():
    keys_dir = "./keys/"
    os.makedirs(keys_dir, exist_ok=True)

    # Generate a new key pair
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()

    # Save private key to file
    with open(os.path.join(keys_dir, "private_key_eddsa.priv"), "wb") as privkey_file:
        privkey_file.write(priv_key.private_bytes(encoding=serialization.Encoding.Raw,
                                                  format=serialization.PrivateFormat.Raw,
                                                  encryption_algorithm=serialization.NoEncryption()))

    # Save public key to file
    with open(os.path.join(keys_dir, "public_key_eddsa.pub"), "wb") as pubkey_file:
        pubkey_file.write(pub_key.public_bytes(encoding=serialization.Encoding.Raw,
                                                format=serialization.PublicFormat.Raw))

    print("EdDSA Private Key saved to:", os.path.join(keys_dir, "private_key_eddsa.priv"))
    print("EdDSA Public Key saved to:", os.path.join(keys_dir, "public_key_eddsa.pub"))

generate_key_ecdsa()
generate_key_eddsa()

