#! /usr/bin/env python
# -*- coding: utf-8 -*-

from Crypto.Util.number import size, long_to_bytes, bytes_to_long, getRandomNBitInteger
from hashlib import sha512
from pwn import process, context, remote
import itertools
import random
import time

fuzzing = "abcdefghijklmnopqrstuvwxyz0123456789QWERTYUIOPASDFGHJKLZXCVBNM"
fuzz = itertools.permutations(fuzzing, 5)
context.log_level = "debug"

k = 2048
e = 0x10001
o = 1024
m = 256

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

def int_add(x1, x2):
	'''
	bit plus
	'''
	return bytes_to_long(long_to_bytes(x1) + long_to_bytes(x2))

def H_hash(x):
	h = sha512(long_to_bytes(x)).hexdigest()
	return int(h, 16)

def F_hash(x):
	h = sha512(long_to_bytes(x/4)).hexdigest()
	return int(h, 16)

def pi_sit_x1(sit, y):
	'''
	inverse operation
	'''
	yu = get_bit(y, sit/2, 1)
	yl = get_bit(y, sit/2, 0)
	xu = yu ^ H_hash(yl)
	xl = yl ^ H_hash(yu ^ F_hash(yl))
	return int_add(xu, xl)

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
	r = remote("120.27.4.96", 14000)
	# r = process("rsa3.py")
	verify(r)
	r.readuntil("token: ")
	token = "d58c9a2aca58a3f2faf17ec5e7deaec6ZHSBHK6e"
	r.sendline(token)
	r.readuntil("P: ")
	P = r.readline().strip()
	P = int(P[2:-1], 16)

	r.readuntil('key:')
	b = getRandomNBitInteger(m/4)
	r.sendline(str(b))

	r.readuntil("n: ")
	n = r.readline().strip()
	n = int(n[2:-1], 16)
	e = 0x10001
	r.readuntil("e2: ")
	e2 = r.readline().strip()
	e2 = int(e2[2:], 16)
	r.readuntil("flag is: ")
	flag = r.readline().strip()
	flag = int(flag[2:-1], 16)
	r.close()
	print "n: ", hex(n)
	print "e: ", hex(e)
	print "e2: ", hex(e2)
	print "flag: ", hex(flag)
	print "=======start attack====="
	t = get_bit(n, 1024, 1)
	print "t: ", hex(t)
	s = pi_sit_x1(o, t)
	print "s: ", hex(s)
	attack_spub = get_bit(s, m, 0)
	# if attack_spub == spub:
	# 	return True
	# else:
	# 	t += 1
	# 	s = pi_sit_x1(o, t)
	# 	attack_spub = get_bit(s, m, 0)
	# 	if attack_spub == spub:
	# 		return True
	# 	else:
	# 		raw_input()
	# 		return False
	attack_spriv = pow(attack_spub, b, P)
	print "spub: ", hex(attack_spub)
	print "spriv: ", hex(attack_spriv)

if __name__ == '__main__':
	main()
	# n = 0
	# for x in xrange(100):
	# 	if main():
	# 		n += 1

	# print "n: {}%".format(n)
