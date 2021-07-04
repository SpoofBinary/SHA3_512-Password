import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet



def TermPrompt():
    Response = input('''new pass | new salt | new algorithm | encrypt | decrypt | hashswap | keyring | !SecureForStorage!
    Type Here : ''')
    if Response in ('ALGORITHM','Algorithm','algorithm','A','a'):
        Algorithm()
    if Response in ('NEWPASS','newpass','NewPass','NP','np','Np','nP'):
        NewPassword()
    if Response in ('ENCRYPT','encrypt','Encrypt','E','e'):
        KeyEncryption()
    if Response in ('DECRYPT','decrypt','Decrypt','D','d'):
        KeyDecryption()
    if Response in ('HASHSWAP','hashswap','HashSwap','HS','hs','Hs','hS'):
        HashSwapper()
    if Response in ('KEYRING','keyring','Keyring','KR','kr','Kr'):
        Keyring()
    if Response in ('SECUREFORSTORAGE','SecureForStorage','secureforstorage','SFS','Sfs','SfS','sfS','sFs','sfs'):
        SecureForStorage()
    if Response in ('NEWSALT','NewSalt','newsalt','NS','Ns','nS','ns'):
        NewSalt()
    if Response in ('NEWALGORITHM','NewAlgorithm','newalgorithm','NA','Na','nA','na'):
        NewAlgorithmKey()
    if Response not in ('ENCRYPT','encrypt','Encrypt','E','e','DECRYPT','decrypt','Decrypt','D','d','HASHSWAP','hashswap','HashSwap','HS','hs','Hs','hS','KEYRING','keyring','Keyring','KR','kr','Kr','NEWPASS','newpass','NewPass','NP','np','Np','nP','SECUREFORSTORAGE','SecureForStorage','secureforstorage','SFS','Sfs','SfS','sfS','sFs','sfs','ALGORITHM','Algorithm','algorithm','A','a','NEWSALT','NewSalt','newsalt','NS','Ns','nS','ns','NEWALGORITHM','NewAlgorithm','newalgorithm','NA','Na','nA','na'):
        return TermPrompt()



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



# Allows User to set Password for Encryption
def NewPassword():
# fetches currently stored password
    file = open('password.key')
    CurrentPassword = file.read()
    file.close()
# creates passive backup of currently stored password
    file = open('oldpassword.key', 'w')
    file.write(CurrentPassword)
    file.close()
# prints to user the currently stored password
    print('This is the currently stored Password : ' + CurrentPassword)
# allows user to enter new input
    NewPassword = input('''Enter New Password Below
    Type Here : ''')
# sets new password to key
    file = open('password.key', 'w')
    file.write(NewPassword)
    file.close()



def KeyEncryption():
# fetches key used to determine what algorithm was used
    file = open('algorithm.key', 'rb')
    key = file.read()
    file.close()
# fetches password string to encode and encrypt in the given algorithm
    file = open('password.key')
    password = file.read()
    file.close()
# sets the password for encryption
    safepass = password
# encodes and encryptes password
    encoder = safepass.encode()
    f = Fernet(key)
    encrypted = f.encrypt(encoder)
# stores encrypted password hash
    file = open('hash.key', 'wb')
    file.write(encrypted)
    file.close()



def KeyDecryption():
# fetches key used to determine what algorithm was used
    file = open('algorithm.key', 'rb')
    algorkey = file.read()
    file.close()
# fetches hashed password
    file = open('hash.key', 'rb')
    hashkey = file.read()
    file.close()
# Decrypts and Decodes hash back into Original Password
    f = Fernet(algorkey)
    decrypted = f.decrypt(hashkey)
    usablepass = decrypted.decode()
    print(usablepass)



def HashSwapper():
# fetches currently stored password hash
    file = open('hash.key' ,'rb')
    oldhash = file.read()
    file.close()
# creates backup incase of accidental hash swap
    file = open ('oldhash.key', 'wb')
    file.write(oldhash)
    file.close()
# asks user for new hash to be stored
    newhash = bytes(input(' Please Enter New Hash : '), 'utf-8')
# overwrites hash key with new hash
    file = open('hash.key', 'wb')
    file.write(newhash)
    file.close()



def Keyring():
# fetches list of Total Keys on Keyring
    file = open('keyring.keys')
    TotalKeys = file.read()
    file.close()
# prints Total Keys to User
    print(TotalKeys)



def SecureForStorage():
# defines file as clean slate
    RedKeyCleaner = ' '
# user warning
    ans = input('''This Will Clean SLate Data of Non Encrypted Files
    such as password.key & oldpassword.key
    for storing the device in case of local breach

    Do You Still Wish To Continue : ''')
# Begins Wiping Data
    if ans in ('YES','Yes','yes','Y','y'):
# Wipes Data
        file = open('password.key', 'w')
        file.write(RedKeyCleaner)
        file.close()
        file = open('oldpassword.key', 'w')
        file.write(RedKeyCleaner)
        file.close()
# Fetches Data to Confirm Clean Slate Presence
        file = open('password.key', 'r')
        password = file.read()
        file.close()
        file = open('oldpassword.key', 'r')
        oldpassword = file.read()
        file.close()
        print('''If Successful This Box Will Be Blank | ''' + password + oldpassword + ''' | ''')
        KeyEncryption()
    if ans not in ('YES','Yes','yes','Y','y'):
        return TermPrompt()



def NewSalt():
# fetches old Salt Key
    file = open('salt.key', 'rb')
    OldSalt = file.read()
    file.close()
# creates passive backup of Salt Key
    file = open('saltbackup.key', 'wb')
    file.write(OldSalt)
    file.close()
# generates new random salt key
    NewSalt = os.urandom(32)
# Writes New Salt to Salt key
    file = open('salt.key', 'wb')
    file.write(NewSalt)
    file.close()



def NewAlgorithmKey():
# fetchees current Algorithm
    file = open('encryptor.key', 'r')
    OldAlgorKey = file.read()
    file.close()
# Creats Passive Backup of Encryptor Key
    file = open('encryptorbackup.key', 'w')
    file.write(OldAlgorKey)
    file.close()
# Writes New Algorithm to Encryptor Key
    NewPhrase = input('''Please Enter New Algorithm Key
    Type Here : ''')
    file = open('encryptor.key', 'w')
    file.write(NewPhrase)
    file.close()



TermPrompt()



### Coded & Scripted entirely by b1n4ry, this script is free to use & requires no license.
### Sun Jul 4 15:18:01
