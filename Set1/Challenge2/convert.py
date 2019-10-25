import binascii

enc_string = "1c0111001f010100061a024b53535009181c"
xor_key = "686974207468652062756c6c277320657965"


def xor_two_strings(str_to_dec, key):
    str_arr = [str_to_dec[i:i + 2] for i in range(0, len(str_to_dec), 2)]
    key_arr = [key[i:i + 2] for i in range(0, len(key), 2)]
    dec_str = ''
    for i in range(len(str_arr)):
        dec_str += chr(int(str_arr[i], 16) ^ int(key_arr[i], 16))
    return dec_str


ret_str = xor_two_strings(enc_string, xor_key)
hex_ret_str = binascii.b2a_hex(ret_str.encode())
print(ret_str)
print("As hex: {}".format(hex_ret_str))
