def PKCS7_Pad(message, block_size):
    return message + bytes(block_size-len(message) % block_size) * \
           (block_size - len(message) % block_size)


def PKCS7_Unpad(cryptmessage):
    padding_len = int(cryptmessage[len(cryptmessage) - 1])
    return cryptmessage[:-padding_len]


def main():
    key = b'YELLOW SUBMARINE'
    pad_key = PKCS7_Pad(key, 20)

    assert(PKCS7_Unpad(pad_key) == key)


if __name__ == '__main__':
    main()