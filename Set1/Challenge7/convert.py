import base64
from Crypto.Cipher import AES

KEY = b'YELLOW SUBMARINE'


def return_decodedB64_from_file(filename):
    with open(filename, 'r') as fp:
        content = fp.read()
    convert_to_ascii = base64.b64decode(content)
    return convert_to_ascii


def decrypt_AES_ECB(ciphertext, plaintext_key):
    cipher = AES.new(plaintext_key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)


ciphertext = return_decodedB64_from_file("encrypted.file")
decrypted_txt = decrypt_AES_ECB(ciphertext, KEY)
print(decrypted_txt)
