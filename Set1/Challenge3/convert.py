enc_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"


def brute_force_single_byte(str_to_dec):
    str_arr = [str_to_dec[i:i + 2] for i in range(0, len(str_to_dec), 2)]
    dec_str = ''
    for key in range(0, 0xff):
        for i in range(len(str_arr)):
            dec_str += chr(int(str_arr[i], 16) ^ key)
        if 'Cook' in dec_str:
            return dec_str, key
        else:
            dec_str = ''
    return "Could not find"


print(brute_force_single_byte(enc_string))
