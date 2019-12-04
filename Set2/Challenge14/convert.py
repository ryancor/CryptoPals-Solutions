#!/usr/bin/env python3
import base64
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Random.random import randint

ciphertext = b'''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK'''

class ECBEncrypt:
    def __init__(self):
        self._key = Random.new().read(AES.block_size)

    def padPKCS7(x, k):
        ch = k - (len(x) % k)
        final = x + bytes([ch] * ch)
        return final

    def aes_ecb_encrypt_data(self, plaintext, key):
        p_plaintext = ECBEncrypt.padPKCS7(plaintext, 16)
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(p_plaintext)

    def encrypt_data(self, text):
        return self.aes_ecb_encrypt_data(text, self._key)


class HarderECBEncrypt(ECBEncrypt):
    def __init__(self, padding):
        super(HarderECBEncrypt, self).__init__()
        self._secret_padding = padding
        self._random_prefix = Random.new().read(randint(0, 255))

    def encrypt(self, data):
        return ECBEncrypt.encrypt_data(self, self._random_prefix + data + self._secret_padding)


def findBlockSize(oracle):
    length = len(oracle.encrypt(b''))
    count = 1
    while True:
        text = bytes([0] * count)
        type = oracle.encrypt(text)
        if len(type) != length:
            return len(type) - length
        count += 1
    return count


def EqualBlock(ciphertext, block_len):
    for i in range(0, len(ciphertext) - 1, block_len):
        if ciphertext[i:i+block_len] == ciphertext[i+block_len:i+2*block_len]:
            return True
    return False


def findPrefixSize(oracle, block_len):
    ciphertext1 = oracle.encrypt(b'')
    ciphertext2 = oracle.encrypt(b'a')

    prefix_len = 0
    for i in range(0, len(ciphertext2), block_len):
        if ciphertext1[i:i+block_len] != ciphertext2[i:i+block_len]:
            prefix_len = i
            break

    for i in range(block_len):
        tmp_input = bytes([0] * (2 * block_len + i))
        ciphertext = oracle.encrypt(tmp_input)
        if EqualBlock(ciphertext, block_len):
            if i != 0:
                return prefix_len + block_len - i
            else:
                return prefix_len

    raise Exception('Not using ECB')


def findNextByte(prefix_len, block_len, decrypted_msg, oracle):
    len_to_use = (block_len - prefix_len - (1 + len(decrypted_msg))) % block_len
    cipher_input = b'A' * len_to_use

    cracking_len = prefix_len + len_to_use + len(decrypted_msg) + 1
    real_cipher = oracle.encrypt(cipher_input)

    for i in range(0xff):
        tmp_cipher = oracle.encrypt(cipher_input + decrypted_msg + bytes([i]))
        if tmp_cipher[:cracking_len] == real_cipher[:cracking_len]:
            return bytes([i])
    return b''


def DecryptOneByteAtTime(oracle):
    block_len = findBlockSize(oracle)
    ciphertext = oracle.encrypt(bytes([0] * 64))
    prefix_len = findPrefixSize(oracle, block_len)
    text_len = len(oracle.encrypt(b'')) - prefix_len

    secret_pad = b''
    for i in range(text_len):
        secret_pad += findNextByte(prefix_len, block_len, secret_pad, oracle)

    return secret_pad


def main():
    plaintext = base64.b64decode(ciphertext)
    oracle = HarderECBEncrypt(plaintext)
    new_plaintext = DecryptOneByteAtTime(oracle)
    if plaintext == new_plaintext[:len(plaintext)]:
        print("Successful match")
    else:
        print("No match...")
        print(plaintext)
        print(new_plaintext)


if __name__ == '__main__':
    main()