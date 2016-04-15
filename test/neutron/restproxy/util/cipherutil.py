# coding:utf-8

# import urllib

from Crypto.Cipher import AES


def rsaEncrypt(text, key):
    pass


def aesEncrypt(text):
    key = '9878*(&^^&)0LLIu(*&^))#$@!KJLKJ0'
    cryptor = AES.new(key, AES.MODE_CBC, '0123456789123456')
    length = 16
    count = text.count('')
    if count < length:
        add = (length-count) + 1
        text = text + (' ' * add)
    elif count > length:
        add = (length-(count % length)) + 1
        text = text + (' ' * add)
    return cryptor.encrypt(text)


def aesDecrypt(text):
    key = '9878*(&^^&)0LLIu(*&^))#$@!KJLKJ0'
    cryptor = AES.new(key, AES.MODE_CBC, '0123456789123456')
    return cryptor.decrypt(text)


def hexStr2Byte(str):

    pass


def str2HexByte(str):
    array = []

    if 16 < len(str):
        for index in range(len(str)):
            array.insert(index, ord(str[index]))
            if 128 < array[index]:
                raise NameError
                ("Illegal characters, the char have to be ascii.")
    else:
        for index in range(len(str)):
            array.insert(index, ord(str[index]))
            if 128 < array[index]:
                raise NameError
                ("Illegal characters, the char have to be ascii.")

        index = len(str)
        while index < 16:
            index += 1
            array[index] = 0

    return array
