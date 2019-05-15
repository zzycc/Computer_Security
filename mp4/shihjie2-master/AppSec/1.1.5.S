
.global _main
.section .text
Addr:
	.string "/bin/sh"
_main:

push	%ebp
mov	%esp,%ebp

mov $11,%eax
lea Addr,%ebx
mov $0, %ecx
mov $0,%edx

int $0x80



leave
ret
