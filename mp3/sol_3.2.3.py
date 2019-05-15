import urllib2
import sys
def get_status(u):
	req = urllib2.Request(u)
	try:
		f = urllib2.urlopen(req)
		return f.code
	except urllib2.HTTPError, e:
		return e.code

get_status("http://cs461-mp3.sprai.org:8081/mp3/shihjie2/?487db27702fe2d9cb3fc04c1823b5ba5890def62960399237c4d66ba9dc7fc17")

padding = ['10','0f','0e','0d','0c','0b','0a','09','08','07','06','05','04','03','02','01']
with open(sys.argv[1]) as c:
	cypher = c.read().strip()
temp = ['0']*16
blocks = []
plain_text = []
origin = []
modify = []
decode = []
for i in range(len(cypher)/32):
	blocks.append(cypher[32*i:32*i+32])
print blocks

for i in range(len(blocks)-1,0,-1):
	print "Block:"+str(i)	
	for j in range(0,16):
		origin.append(blocks[i-1][j*2:j*2+2])
		modify.append(blocks[i-1][j*2:j*2+2])
		decode.append(blocks[i][j*2:j*2+2])

	for index in range(15,-1,-1):
		for k in range(0,256):
			if k^int(origin[index],16)!=0:
				modify[index] = format(k^16,'x').zfill(2)
			url = "http://72.36.89.237:8081/mp3/shihjie2/?"+''.join(modify)+''.join(decode)
			if get_status(url)==404:
				print "Test"
				print temp
				temp[index] = format(k,'x').zfill(2)
				if index==0:
					plain_text = [temp]+plain_text
					origin = []
					modify = []
					decode = []
					temp = ['0']*16
					print "now"+''.join([chr(int(character, 16)) for partial in plain_text for character in partial])
				else:
					for padCount in range(1, 17-index):			
						modify[-padCount] = format(int(padding[16-index - padCount + 1], 16)  ^ int(temp[-padCount], 16) ^ int(origin[-padCount], 16),'x').zfill(2)
				break

print plain_text
result = ''.join([chr(int(character,16)) for i in plain_text for character in i])
for x in result:
	if (x < '\x20'):
		result = result.replace(x,'')
with open(sys.argv[2], 'w') as o:
	o.write(result)

