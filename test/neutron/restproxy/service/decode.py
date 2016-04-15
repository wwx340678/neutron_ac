# coding:utf-8
'''
Created on 2014-8-2

@author: l00284247
'''


from Crypto.Cipher import AES


def aesDecrypt(text):
    key = '9878*(&^^&)0LLIu(*&^))#$@!KJLKJ0'
    cryptor = AES.new(key, AES.MODE_CBC, '0123456789123456')
    return cryptor.decrypt(text)

password = raw_input('enter encode password:')

print aesDecrypt(password.decode('BASE64')).strip()
