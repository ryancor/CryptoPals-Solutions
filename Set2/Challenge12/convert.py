#!/usr/bin/env python3
import string
import random
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

ciphertext = b'''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK'''
key = None


def padPKCS7(x, k):
    ch = k - (len(x) % k)
    final = x + bytes([ch] * ch)
    return final


def aes_ecb_encrypt_data(plaintext, key):
    extra = len(plaintext) % 16
    if extra > 0:
        padding = random.choice(string.letters)
        plaintext = plaintext + (padding * (16 - extra))
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def encrypt_data(text):
    global key
    if key is None:
        key = get_random_bytes(16)
    text = padPKCS7(text + b64decode(ciphertext), 16)
    return aes_ecb_encrypt_data(text, key)


def findBlockSize(encrypt_data):
    length = len(encrypt_data(b''))
    count = 1
    while True:
        text = bytes([0] * count)
        type = encrypt_data(text)
        if len(type) != length:
            return len(type) - length
        count += 1
    return count


def IsECB(encryption_type, blocksize):
    text = get_random_bytes(blocksize) * 2
    type = encrypt_data(text)
    # if the first 16 bytes dont match the last 16 bytes, then its not ECB
    if type[0:blocksize] != type[blocksize:2*blocksize]:
        raise Exception('Not using ECB')


def findNextByte(encrypt_data, blocksize, knownBytes):
    text = bytes([0] * (blocksize - (len(knownBytes) % blocksize) - 1))
    decrypted = {}
    for i in range(256):
        type = encrypt_data(text + knownBytes + bytes([i]))
        decrypted[type[0:len(text) + len(knownBytes) + 1]] = i
    type = encrypt_data(text)
    word = type[0:len(text) + len(knownBytes) + 1]
    if word in decrypted:
        return decrypted[word]
    return None


def main():
    blocksize = findBlockSize(encrypt_data)
    IsECB(encrypt_data, blocksize)
    text = b''
    while True:
        byte = findNextByte(encrypt_data, blocksize, text)
        if byte is None:
            break
        text += bytes([byte])
    print(text)

if __name__ == "__main__":
    main()