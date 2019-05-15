import sys
import hashlib

input1_file = sys.argv[1]
input2_file = sys.argv[2]
out_file = sys.argv[3]
out = ""

with open(input1_file) as i:
	input1_content = i.read().strip()
with open(input2_file) as p:
	p_content = p.read().strip()
input_m = hashlib.sha256()
input_m.update(input1_content)
input_result = input_m.hexdigest()
input_binary = bin(int(input_result,16))[2:]
input_binary=input_binary.zfill(256)
input_binary = str(input_binary)
print len(input_binary)
print input_binary

perturbed = hashlib.sha256()
perturbed.update(p_content)
perturbed_result = perturbed.hexdigest()
perturbed_binary = bin(int(perturbed_result,16))[2:]
perturbed_binary=perturbed_binary.zfill(256)
perturbed_binary = str(perturbed_binary)
print len(perturbed_binary)
print perturbed_binary
h=0
for i in range(0,len(input_binary)):
	if input_binary[i] != perturbed_binary[i]:
		h = h + 1



with open(out_file, "w") as out:
	out.write(format(h,'x'))


