import sys
cypher_file = sys.argv[1]
key_file = sys.argv[2]
out_file = sys.argv[3]
out = ""
with open(cypher_file) as cipher:
	with open(key_file) as key:
		file_content = cipher.read().strip()
		key_content = key.read().strip()
		with open(out_file,"w") as output:
			for i in range(0,len(file_content)):
				if file_content[i] in key_content:
					out = out + chr(ord('A')+key_content.index(file_content[i]))
				else:
					out = out + file_content[i]
			output.write(out)
			#print out
