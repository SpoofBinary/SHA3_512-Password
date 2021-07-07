import os
import base64
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet



def TermPrompt():
    Response = input('''RGPassphrase | New Pass | New Salt | New Algorithm | Encrypt | Decrypt | HashSwap | KeyRing | Binary | !SecureForStorage!
    Type Here : ''')
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
    if Response in ('BINARY','Binary','binary','B','b'):
        Binary()
    if Response in ('RGPASSPHRASE','rgPASSPHRASE','RgPASSPHRASE','rGPASSPHRASE','RGpassphrase','rgpassphrase','Rgpassphrase','rGpassphrase','RGPassPhrase','rgpPassPhrase','RgPassPhrase','rGPassPhrase',):
        RandomlyGeneratedPassPhrase()
    if Response not in ('ENCRYPT','encrypt','Encrypt','E','e','DECRYPT','decrypt','Decrypt','D','d','HASHSWAP','hashswap','HashSwap','HS','hs','Hs','hS','KEYRING','keyring','Keyring','KR','kr','Kr','NEWPASS','newpass','NewPass','NP','np','Np','nP','SECUREFORSTORAGE','SecureForStorage','secureforstorage','SFS','Sfs','SfS','sfS','sFs','sfs','ALGORITHM','Algorithm','algorithm','A','a','NEWSALT','NewSalt','newsalt','NS','Ns','nS','ns','NEWALGORITHM','NewAlgorithm','newalgorithm','NA','Na','nA','na','BINARY','Binary','binary','B','b','RGPASSPHRASE','rgPASSPHRASE','RgPASSPHRASE','rGPASSPHRASE','RGpassphrase','rgpassphrase','Rgpassphrase','rGpassphrase','RGPassPhrase','rgpPassPhrase','RgPassPhrase','rGPassPhrase'):
        return TermPrompt()



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
    key = file.read()
    file.close()
# fetches hashed password
    file = open('hash.key', 'rb')
    hashkey = file.read()
    file.close()
# Decrypts and Decodes hash back into Original Password
    f = Fernet(key)
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
    ans = input(TotalKeys + '''
    Currently Stowed Keys Have Been Listed Above
    Would You Like To Store Another One ? 
    Type Here : ''')
    if ans in ('YES','Yes','yes','Y','y'):
        NewHashKey = input('''Enter The Key You Would Like To Stow
        Type Here : ''')
        file = open('keyring.keys', 'w')
        file.write(TotalKeys + '''

''' + NewHashKey)
        file.close()
    if ans in ('NO','No','no','N','n'):
        print('')


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
        file = open('binaryhash.key', 'w')
        file.write(RedKeyCleaner)
        file.close()
# Fetches Data to Confirm Clean Slate Presence
        file = open('password.key', 'r')
        password = file.read()
        file.close()
        file = open('oldpassword.key', 'r')
        oldpassword = file.read()
        file.close()
        file = open('binaryhash.key', 'r')
        binaryhash = file.read()
        file.close()
        print('''If Successful This Box Will Be Blank | ''' + password + oldpassword + binaryhash + ''' | ''')
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



def remove_spaces(str1):
    str1 = str1.replace(' ', '')
    return str1



def DecodeBinaryString(s):
    return ''.join(chr(int(s[i*8:i*8+8],2)) for i in range(len(s)//8))



def Binary():
    ans = input('''Encrypt | Decrypt
    Type Here : ''')
# Encrypt Option
    if ans in ('ENCRYPT','Encrypt','encrypt','E','e'):
        String = input('''Please Input Binary String
Type Here : ''')
# encrypts string into binary format
        BinaryHash = ' '.join(format(ord(i), '08b') for i in String)
# Reverse binary hash for secure storage
        BHReversed = BinaryHash[::-1]
# writes binary to file
        file = open('binaryhash.key', 'w')
        file.write(BHReversed)
        file.close()
        print(BHReversed)
# decrypts binary into string format
    if ans in ('DECRYPT','Decrypt','decrypt','D','d'):
# fetches for Reversed Binary in binaryhash.key
        file = open('binaryhash.key', 'r')
        BinaryDecryptReversed = file.read()
        file.close()
# Unreverses reversed binary from secured storage
        BinaryNormal = BinaryDecryptReversed[::-1]
# removes spacaes for binary decoding
        BinaryString = remove_spaces(BinaryNormal)
# decodes binary to string
        DecodedString = DecodeBinaryString(BinaryString)
# prints to user
        print(DecodedString)



# Creates Random Iterations of PassPhrases
def RGPass():
    b = open('dictionary.py').read().splitlines()
    n1 = random.choice(range(1,370000))
    n2 = random.choice(range(1,370000))
    n3 = random.choice(range(1,370000))
    n4 = random.choice(range(1,370000))
    n5 = random.choice(range(1,370000))
    n6 = random.choice(range(1,370000))
    n7 = random.choice(range(1,370000))
    n8 = random.choice(range(1,370000))
    n9 = random.choice(range(1,370000))
    x = [n1, n2, n3, n4, n5, n6, n7, n8, n9]
    s = '#'
    z = []
    for index in x:
        z.append(b[index])
    y = '#'.join(z)
    v = str(y.replace("'",''))
    h = v.split(s)
    o = '24#68%975@31'
    r = o.join(h)
    file = open('PPG.key', 'a')
    file.write('''
''' + r + 
'''
''')
    file.close()
def RGPass1():
    RGPass()
def RGPass2():
    RGPass()
    RGPass()
def RGPass5():
    RGPass2()
    RGPass2()
    RGPass1()
def RGPass10():
    RGPass5()
    RGPass5()
def RGPass15():
    RGPass10()
    RGPass5()
def RGPass20():
    RGPass10()
    RGPass10()
def RGPass50():
    RGPass10()
    RGPass10()
    RGPass10()
    RGPass10()
    RGPass10()
def RGPass100():
    RGPass50()
    RGPass50()
def RandomlyGeneratedPassPhrase():
    he = input('''How Many Iterations ? 
Type Here : ''')
    if he not in ('1','2','10','15','20','50','100'):
        print('Please Use Listed Numbers Only')
    if he in ('1'):
        print(RGPass1())
        return print(he + ' iterations logged successfully')
    if he in ('2'):
        print(RGPass2())
        return print(he + ' iterations logged successfully')
    if he in ('5'):
        print(RGPass2())
        print(RGPass2())
        print(RGPass1())
        return print(he + ' iterations logged successfully')
    if he in ('10'):
        print(RGPass10())
        return print(he + ' iterations logged successfully')
    if he in ('15'):
        print(RGPass15())
        return print(he + ' iterations logged successfully')
    if he in ('20'):
        print(RGPass20())
        return print(he + ' iterations logged successfully')
    if he in ('50'):
        print(RGPass50())
        return print(he + ' iterations logged successfully')
    if he in ('100'):
        print(RGPass100())
        return print(he + ' iterations logged successfully')
    if he not in ('1','2','10','15','20','50','100'):
        return print('Please Use Listed Numbers Only')



TermPrompt()



### Coded & Scripted entirely by b1n4ry, this script is free to use & requires no license.
### Sun Jul 4 15:18:01
