def Check_ECB_Encrypted_Line(filename, block_size):
    with open(filename, 'r') as fp:
        line = fp.readline()
        cnt = 1
        while line:
            content = line.strip().decode('hex')
            block_count = len(content) / block_size
            for i in range(block_count):
                for j in range(i+1, block_count):
                    first_block = content[i * block_size:(i + 1) * block_size]
                    second_block = content[j * block_size:(j + 1) * block_size]
                    print("Checking blocks: {0}<=>{1}".format(first_block.encode('hex'), second_block.encode('hex')))
                    if first_block == second_block:
                        return line     # return hex string
            line = fp.readline()
            cnt += 1
    return False


ciphertext = Check_ECB_Encrypted_Line("encrypted.file", 16)
if ciphertext != False:
    print("Found encrypted line: {}".format(ciphertext))
else:
    print("Could not find encrypted line")