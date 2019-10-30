'''
    For every loop we need to check each 16 bytes against the next set of 16 bytes
    i=0:16 j=16:32
    i=0:16 j=32:48
    i=0:16 j=48:64
    i=0:16 j=64:80
    i=0:16 j=80:96
    i=0:16 j=96:112
    i=0:16 j=112:128
    i=0:16 j=128:144
    ...
    i=16:32 j=32:48
    i=16:32 j=48:64
    i=16:32 j=64:80
    ...
    if contents_of(i == j): then thats the encrypted line
'''

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