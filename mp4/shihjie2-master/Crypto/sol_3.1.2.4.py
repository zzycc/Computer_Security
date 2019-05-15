import sys
import math
from Crypto.Cipher import AES
cypher_file = sys.argv[1]
key_file = sys.argv[2]
modulo_file = sys.argv[3]
out_file = sys.argv[4]
out = ""

with open(cypher_file) as cipher:
	cipher_content = cipher.read().strip()
with open(modulo_file) as modulo:
	modulo_content = modulo.read().strip()
with open(key_file) as key:
	key_content = key.read().strip()
cipher_integer=int(cipher_content,16)
key_integer=int(key_content,16)
modulo_integer=int(modulo_content,16)

result=pow(cipher_integer,key_integer,modulo_integer)
print result
result_hex = format(result,'x')

with open(out_file, "w") as out:
	out.write(result_hex)


