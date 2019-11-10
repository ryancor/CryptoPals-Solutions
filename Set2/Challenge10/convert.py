import base64
from Crypto.Cipher import AES

KEY = b'YELLOW SUBMARINE'
IV = b'\x00' * AES.block_size


def xor_bytes(string_to_dec, key):
    res = bytearray()
    for string_b, key_b in zip(string_to_dec, key):
        res.append(string_b ^ key_b)
    return res


def PKCS7_Unpad(cryptmessage):
    padding_len = int(cryptmessage[len(cryptmessage) - 1])
    return cryptmessage[:-padding_len]


def return_decodedB64_from_file(filename):
    with open(filename, 'r') as fp:
        content = fp.read()
    convert_to_ascii = base64.b64decode(content)
    return convert_to_ascii


def decrypt_AES_ECB(ciphertext, plaintext_key):
    cipher = AES.new(plaintext_key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)


def decrypt_AES_CBC(ciphertext, key, iv):
    plaintext = bytes()
    cipher_block = ciphertext[:AES.block_size]
    plaintext_tmp = decrypt_AES_ECB(cipher_block, key)
    plaintext += xor_bytes(plaintext_tmp, iv)

    for i in range(1, len(ciphertext)//AES.block_size):
        cipher_block = ciphertext[i*AES.block_size:i*AES.block_size+AES.block_size]
        plaintext_tmp = decrypt_AES_ECB(cipher_block, key)
        plaintext += xor_bytes(plaintext_tmp, ciphertext[(i-1)*AES.block_size:(i-1)*AES.block_size+AES.block_size])
    plaintext = PKCS7_Unpad(plaintext)
    return plaintext


ciphertext = return_decodedB64_from_file("encrypted.file")
decrypted_txt = decrypt_AES_CBC(ciphertext, KEY, IV)
print(decrypted_txt)
