from random import randint
from Crypto.Cipher import AES
from Crypto.Cipher.AES import block_size
from Crypto import Random


def pad_with_bytes(data):
    return Random.new().read(block_size) + data + Random.new().read(randint(16, 16))


def aes_ecb_encrypt_data(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def aes_cbc_encrypt_data(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext)


def encrypt_data(plaintext):
    p_plaintext = pad_with_bytes(plaintext)
    rand_key = Random.new().read(block_size)
    rand_iv = Random.new().read(randint(16, 16))

    print("Padded Plaintext: {}".format(p_plaintext))
    print("IV : {}".format(rand_iv.encode('hex')))
    print("Key: {}".format(rand_key.encode('hex')))

    if randint(0, 1) == 0:
        return "ECB", aes_ecb_encrypt_data(p_plaintext, rand_key)
    else:
        return "CBC", aes_cbc_encrypt_data(p_plaintext, rand_key, rand_iv)


def detect_cipher(ciphertext):
    for i in range(0, len(ciphertext), block_size):
        chunks = ciphertext[i:i + block_size]
        # checking if ciphertext[16:32] == ciphertext[32:48], then ECB
    num_of_dups = len(chunks) - len(set(chunks))
    if num_of_dups > 0:
        return "ECB"
    else:
        return "CBC"


def main():
    input_data = "YELLOW SUBMARINE"
    _, encrypted_text = encrypt_data(input_data)
    detected_cipher = detect_cipher(encrypted_text)
    print("{} <=> {} text: {}".format(_, detected_cipher, encrypted_text.encode('hex')))


if __name__ == '__main__':
    main()