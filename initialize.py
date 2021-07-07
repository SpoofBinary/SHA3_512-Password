file = open('keyring.keys', 'x')
file.close()
file = open('algorithm.key', 'x')
file.close()
file = open('binaryhash.key', 'x')
file.close()
file = open('encryptor.key', 'x')
file.close()
file = open('encryptorbackup.key', 'x')
file.close()
file = open('salt.key', 'x')
file.close() 
file = open('saltbackup.key', 'x')
file.close()
file = open('hash.key', 'x')
file.close()
file = open('oldhash.key', 'x')
file.close() 
file = open('password.key', 'x')
file.close() 
file = open('oldpassword.key', 'x')
file.close() 
file = open('PPG.key', 'x')
file.close()
import os
import base64
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
def Algorithm():
# grabs the encryptor string
    file = open('encryptor.key')
    encryptkey = file.read()
    file.close()
# sets the string for method of algorithmic encryption
    encryptor = encryptkey
# encoding and encrypting the string used to 
    encoder = encryptor.encode()
# grabs salt key
    file = open('salt.key', 'rb')
    saltkey = file.read()
    file.close()
# sets the salt for algorithm
    salt = saltkey
# Algorithm KDF configuration
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_512(),
        length=32,
        salt=salt,
        iterations=1000000,
        backend=default_backend()
    )
# sets algorithm key
    key = base64.urlsafe_b64encode(kdf.derive(encoder))
    file = open('algorithm.key', 'wb')
    file.write(key)
    file.close()
Algorithm()
