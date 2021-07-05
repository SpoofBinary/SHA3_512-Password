# put any character string inside of encryptorkey_string quotes
encryptorkey_string = ''
# put any salt key inside of saltkey_salt quotes
saltkey_salt = b''
# hashkey hashes
# (i.e.) Gmail = 'haaaaaaaaaa28dh2dka2d2d8a2hdka2hdak2ufhdf7geakfa2idhdiahfdfkiwf73hadika2dh82ad2da90jaed8fghsg3fs=s3f323jd'
WebsiteName = 'Password Encrypted With SHA3_512'
# prints usable information back to user incase of accidental full data redkey
print('Algorithm : ' + encryptorkey_string)
print('Salt : ' + str(saltkey_salt))
print('Account : ' + WebsiteName)
