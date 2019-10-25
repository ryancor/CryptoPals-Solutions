def brute_force_single_byte(str_to_dec, strToFind=""):
    # temp = open("temp.file", "w")
    str_arr = [str_to_dec[i:i + 2] for i in range(0, len(str_to_dec), 2)]
    dec_str = ''
    for key in range(0, 0xff):
        for i in range(len(str_arr)):
            dec_str += chr(int(str_arr[i], 16) ^ key)
        # temp.write(dec_str + "\n")				# we use this to get clues about what string to search for
        if strToFind in dec_str:
            return dec_str, key
        else:
            pass
        dec_str = ''
    return "Could not find text", "Z9"


def brute_force_single_byte_from_file(filename, output):
    f = open(output, 'w')
    with open(filename) as fp:
        line = fp.readline()
        cnt = 1
        while line:
            line = line.strip()
            retString, retKey = brute_force_single_byte(line, "party")
            if retKey != "Z9":
                print("Found array containing plaintext: {}".format(line))
                f.write("Line: {}; Key: {} => Text: {}\n".format(cnt, retKey, retString))
                break  # comment this break when we dont know the string to find
            line = fp.readline()
            cnt += 1
    return f.close(), fp.close()


brute_force_single_byte_from_file("encrypted.file", "decrypted.file")
