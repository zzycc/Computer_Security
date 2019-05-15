import sys
from Crypto.Cipher import AES
cypher_file = sys.argv[1]
key_file = sys.argv[2]
iv_file = sys.argv[3]
out_file = sys.argv[4]
out = ""

with open(cypher_file) as cipher:
	cipher_content = cipher.read().strip()
with open(iv_file) as iv:
	iv_content = iv.read().strip()
with open(key_file) as key:
	key_content = key.read().strip()
key_hex=key_content.decode("hex")
iv_hex=iv_content.decode("hex")
cipher_hex = cipher_content.decode("hex")
decryption_suite = AES.new(key_hex, AES.MODE_CBC, iv_hex)
plain_text = decryption_suite.decrypt(cipher_hex)
with open(out_file, "w") as out:
	out.write(plain_text)


