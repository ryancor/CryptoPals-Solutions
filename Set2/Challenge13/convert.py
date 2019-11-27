#!/usr/bin/env python3
from Crypto import Random
from Crypto.Cipher import AES


class ECBEncrypt:
    def __init__(self):
        self._key = Random.new().read(AES.block_size)

    def encrypt_data(self, text):
        text = encode_json(profile_for(text))
        bytes_to_enc = text.encode()
        return aes_ecb_encrypt_data(bytes_to_enc, self._key)

    def decrypt_data(self, ciphertext):
        cipher = AES.new(self._key, AES.MODE_ECB)
        return cipher.decrypt(ciphertext)


def padPKCS7(x, k):
    ch = k - (len(x) % k)
    final = x + bytes([ch] * ch)
    return final


def aes_ecb_encrypt_data(plaintext, key):
    p_plaintext = padPKCS7(plaintext, 16)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(p_plaintext)


def encode_json(obj):
    ciphertext = ''
    for item in obj.items():
        ciphertext += item[0] + '=' + str(item[1]) + '&'
    return ciphertext[:-1]


def json_parse(ciphertext):
    output = {}
    attrs = ciphertext.split('&')

    for attr in attrs:
        values = attr.split('=')
        keys = int(values[0]) if values[0].isdigit() else values[0]
        try:
            value = int(values[1]) if values[1].isdigit() else values[1]
        except Exception as error:
            value = 'admin'
        output[keys] = value

    return output


def profile_for(email):
    email = email.replace('&', '').replace('=', '')
    return {
        'email': email,
        'uid': 10,
        'role': 'user'
    }


def ecb_cut_and_paste(ciphertext_block):
    prefix_len = AES.block_size - len("email=")
    suffix_len = AES.block_size - len("admin")
    email1 = 'x' * prefix_len + "admin" + (chr(suffix_len) * suffix_len)
    encrypted1 = ciphertext_block.encrypt_data(email1)

    email2 = "ryancor@me.com"
    encrypted2 = ciphertext_block.encrypt_data(email2)

    forced = encrypted2[:32] + encrypted1[16:32]
    return forced


def main():
    ecb_block = ECBEncrypt()
    ciphertext = ecb_cut_and_paste(ecb_block)

    plaintext = ecb_block.decrypt_data(ciphertext)
    parsed_plaintext = json_parse(plaintext[:37].decode())
    if 'role' in parsed_plaintext:
        print("User: ")
        print(parsed_plaintext['role'] == 'user')
    elif 'roleadmin' in parsed_plaintext:
        print("Admin: ")
        print(parsed_plaintext['roleadmin'] == 'admin')
    else:
        print(parsed_plaintext)


if __name__ == '__main__':
    main()