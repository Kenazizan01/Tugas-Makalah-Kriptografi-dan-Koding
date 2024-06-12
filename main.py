from generate_key import *
from sign import *
from verify import *

keyfilename_ecdsa = input("Input key file name: ")
generate_key_ecdsa(keyfilename_ecdsa)

keyfilename_eddsa = input("Input key file name: ")
generate_key_eddsa(keyfilename_eddsa)

filename = input("input file name: ")
key = input("input key file name: ")
sign_ecdsa_file(filename,key)
sign_eddsa_file(filename,key)

filename = input("input file name: ")
key = input("input key file name: ")
signature_filename = input("input file signature name: ")
verify_ecdsa_signature(filename,signature_filename,key)
verify_eddsa_signature(filename,signature_filename,key)

