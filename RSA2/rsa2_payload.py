#! /usr/bin/env python
# -*- coding: utf-8 -*-

from Crypto.Util.number import size, long_to_bytes, bytes_to_long
from Crypto.Cipher import DES
from hashlib import sha512
from pwn import process, context, remote
import itertools
import time

fuzzing = "abcdefghijklmnopqrstuvwxyz0123456789QWERTYUIOPASDFGHJKLZXCVBNM"
fuzz = itertools.permutations(fuzzing, 5)
context.log_level = "debug"

k = 2048
key = "abcdefg1"

def pi_b(x, m):
	'''
	m:
	1: encrypt
	0: decrypt
	'''	
	enc = DES.new(key)
	if m:
		method = enc.encrypt
	else:
		method = enc.decrypt
	s = long_to_bytes(x)
	sp = [s[a:a+8] for a in xrange(0, len(s), 8)]
	r = ""
	for a in sp:
		r += method(a)
	return bytes_to_long(r)


def get_bit(number, n_bit, dire):
	'''
	dire:
		1: left
		0: right
	'''

	if dire:
		sn = size(number)
		if sn % 8 != 0:
			sn += (8 - sn % 8)
		return number >> (sn-n_bit)
	else:
		return number & (pow(2, n_bit) - 1)

def sha512_proof(fuzz, prefix, verify):
	y = len(verify)
	while True:
		try:
			padd = "".join(fuzz.next())
		except StopIteration:
			break
		r = sha512(prefix + padd).hexdigest()
		if verify in r:
			return padd

def verify(r):
	r.readuntil("Prefix: ")	
	prefix = r.readline()
	prefix = prefix.decode('base64')
	t1 = time.time()
	proof = sha512_proof(fuzz, prefix, "fffffff")
	print time.time() - t1
	r.send(proof.encode('base64'))

def main():
	r = remote("115.159.191.193", 13000)
	# r = process("rsa2.py")
	verify(r)
	r.readuntil("token: ")
	token = "d58c9a2aca58a3f2faf17ec5e7deaec6ZHSBHK6e"
	r.sendline(token)

	# r.readuntil("p4: ")
	# p_4 = r.readline().strip()
	# p_4 = int(p_4[2:-1], 16)

	r.readuntil("n: ")
	n = r.readline().strip()
	n = int(n[2:-1], 16)
	e = 0x10001
	r.readuntil("e2: ")
	e2 = r.readline().strip()
	e2 = int(e2[2:], 16)
	print "n: ", hex(n)
	print "e: ", hex(e)
	print "e2: ", hex(e2)
	r.readuntil("flag is: ")
	flag = r.readline().strip()
	flag = int(flag[2:-1], 16)
	print "flag: ", hex(flag)
	print "=======start attack====="
	n1 = get_bit(n, 3*k/8, 1)
	# print "n1: ", hex(n1)
	p4 = pi_b(get_bit(n1, 5*k/16, 0), 0)
	# if p_4 == p4:
	# 	return True
	# else:
	# 	return False
	print "p4: ", hex(p4)
	r.close()

if __name__ == '__main__':
	# n = 0
	# for x in xrange(100):
	# 	if main():
	# 		n += 1

	# print "n: {}%".format(n)
	main()