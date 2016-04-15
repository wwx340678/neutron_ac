# coding:utf-8
'''
Created on 2014-8-2

@author: l00284247
'''

import sys
from Crypto.Cipher import AES


def aesEncrypt(text):
    key = '9878*(&^^&)0LLIu(*&^))#$@!KJLKJ0'
    cryptor = AES.new(key, AES.MODE_CBC, '0123456789123456')
    length = 16
    count = len(text)
    if count < length:
        add = length-count
        text = text + (' ' * add)
    elif count > length:
        add = length-(count % length)
        text = text + (' ' * add)
    return cryptor.encrypt(text)

# password = raw_input('enter password:')

print aesEncrypt(sys.argv[1]).encode('BASE64')
