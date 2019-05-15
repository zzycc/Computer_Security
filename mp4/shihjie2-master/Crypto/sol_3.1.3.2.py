import sys

input_file = sys.argv[1]
out_file = sys.argv[2]
out = ""
def WHA(input_binary):
	mask = 0x3FFFFFFF
	outHash = 0
	for i in input_binary:
		i_ascii = ord(i)
		intermediate_value = ((i_ascii^0xCC)<<24)|((i_ascii^0x33)<<16)|((i_ascii^0xAA)<<8)|((i_ascii^0x55))
		outHash = (outHash&mask)+(intermediate_value&mask)
	return "0x"+format(outHash,"x")
#print WHA("Hello world!")
#print WHA("I am Groot.")
with open(input_file) as i:
	input_content = i.read().strip()

with open(out_file, "w") as out:
	out.write(WHA(input_content))
collision = "WEHN OTHLELO DEDCIES HE WNATS TO POIOSN DESDEMNOA THIS VILLIAN SUGGESTS TAHT EH ELSTRANG REH TEADINS"
#print WHA(collision)
#print WHA(input_content)


