import binascii

str1_to_enc = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key = "ICE"


def repeating_xor_key(str_to_dec, key_b):
    res = ''
    for i in range(len(str_to_dec)):
        res += chr(ord(str_to_dec[i]) ^ ord(key_b[i % len(key_b)]))
    return binascii.b2a_hex(res)


assert (repeating_xor_key(str1_to_enc,
                          key) == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
                                  "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        ) != 0, "Failed"
