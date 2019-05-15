import urllib
import sys
from pymd5 import md5,padding

query_file = sys.argv[1]
command_file = sys.argv[2]
output_file = sys.argv[3]

with open(query_file) as q:
	query = q.read().strip()
with open(command_file) as c:
	command = c.read().strip()

token = query[query.find('token=')+6:query.find('&user')]

h = md5(state=token.decode("hex"),count = 512)
h.update(command)
x = h.hexdigest()

result=query[0:6]+x+query[6+32:]+urllib.quote(padding((len(query[39:])+8)*8))+command

with open(sys.argv[3],'w') as w:
	w.write(result)
