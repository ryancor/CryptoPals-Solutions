# This file uses Python3
import base64


def hamming_distance(str1, str2):
    distance = 0
    for char1, char2 in zip(str1, str2):
        diff = char1 ^ char2
        distance += sum([1 for bit in bin(diff) if bit == '1'])
    return distance


def return_decodedB64_from_file(filename):
    with open(filename, 'r') as fp:
        content = fp.read()
    convert_to_ascii = base64.b64decode(content)
    return convert_to_ascii


def xor_single_byte(string_to_dec, key):
    res = b''
    for string_b, key_b in zip(string_to_dec, key):
        res += bytes([string_b ^ key_b])
    return res


def brute_force_single_byte(data):
    possible_plaintext = None
    ascii_text_chars = list(range(97, 122)) + [32]
    for i in range(2 ** 8):
        candidate_key = i.to_bytes(1, byteorder='big')
        key_bytes = candidate_key * len(data)
        candidate_message = xor_single_byte(data, key_bytes)
        rand_byte = sum([x in ascii_text_chars for x in candidate_message])

        if possible_plaintext == None or rand_byte > possible_plaintext['rand_byte']:
            possible_plaintext = {"message": candidate_message, 'rand_byte': rand_byte, 'key': candidate_key}
    return possible_plaintext


def score_vigenere_key_s(can_key_size, data):
    slice_s = 2 * can_key_size
    nb_measure = len(data) // slice_s - 1

    score = 0
    for i in range(nb_measure):
        s = slice_s
        k = can_key_size
        slice_1 = slice(i*s, i*s + k)
        slice_2 = slice(i*s + k, i*s + 2*k)

        score += hamming_distance(data[slice_1], data[slice_2])

    score /= can_key_size
    score /= nb_measure
    return score


def vigenere_key_len(data, min_length=2, max_length=30):
    key = lambda x: score_vigenere_key_s(x, data)
    return min(range(min_length, max_length), key=key)


def break_repeating_xor_key(data):
    key_s = vigenere_key_len(data)
    key = bytes()
    msg_p = list()

    for i in range(key_s):
        part = brute_force_single_byte(bytes(data[i::key_s]))
        key += part["key"]
        msg_p.append(part["message"])

    msg = bytes()
    for i in range(max(map(len, msg_p))):
        for part in msg_p:
            if len(part) >= i + 1:
                msg += bytes([part[i]])

    return {'message':msg, 'key': key}


assert(hamming_distance(b"this is a test", b"wokka wokka!!!") == 37)

hex_data = return_decodedB64_from_file("encrypted.file")
result = break_repeating_xor_key(hex_data)
print("Key: {}\n".format(result['key']))
print("Message: {}\n".format(result['message'].decode()))
