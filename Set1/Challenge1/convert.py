import base64

hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
n = 2
hex_split = [hex_str[i:i+n] for i in range(0, len(hex_str), n)]

str_to_dec = ''
for i in range(len(hex_split)):
	str_to_dec += chr(int(hex_split[i], 16))
print(str_to_dec)
print("As b64: {}".format(base64.b64encode(str_to_dec.encode())))
