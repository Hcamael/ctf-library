#! /usr/bin/env python
# -*- coding: utf-8 -*-

from Crypto.Util.number import size, getPrime, long_to_bytes, bytes_to_long, isPrime, getRandomNBitInteger
from libnum import invmod, gcd
from flag import get_flag
from hashlib import sha512
import random
import time
import signal

__author__ = 'Hcamael'

k = 2048
e = 0x10001
o = 1024
m = 256
signal.alarm(40)


def m_exit(n):
	print "==============Game Over!================="
	exit(n)

def verify():
	print "Proof of Work"
	with open("/dev/urandom") as f:
		prefix = f.read(5)
	print "Prefix: %s" %prefix.encode('base64')
	try:
		suffix = raw_input()
		s = suffix.decode('base64')
	except:
		m_exit(-1)
	r = sha512(prefix + s).hexdigest()
	if "fffffff" not in r:
		m_exit(-1)

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
	return bytes_to_long(long_to_bytes(x1) + long_to_bytes(x2))

def H_hash(x):
	h = sha512(long_to_bytes(x)).hexdigest()
	return int(h, 16)

def F_hash(x):
	h = sha512(long_to_bytes(x/4)).hexdigest()
	return int(h, 16)

def pi_sit_x(sit, x):
	'''
	default sit = 1024
	'''
	xu = get_bit(x, sit/2, 1)
	xl = get_bit(x, sit/2, 0)
	yu = F_hash(H_hash(xu) ^ xl) ^ xu
	yl = H_hash(xu) ^ xl
	return int_add(yu, yl)

def get_pkey():
	print "DH key exchange system:"
	P = getPrime(m)
	print "P: ", hex(P)
	G = getRandomNBitInteger(m)
	a = getRandomNBitInteger(m/4)
	Ya = pow(G, a, P)
	print "Please enter you secret key: "
	try:
		b = raw_input()
		b = int(b)
		assert size(b) == m/4
	except:
		m_exit(-1)
	Yb = pow(G, b, P)
	K = pow(Yb, a, P)
	return (Ya, K)

def GenPrimeWithOracle(spriv, L, e):
	'''
	Generate p
	'''
	T = L/2 + 64
	T1 = L - T
	PRF = random.Random()
	PRF.seed(spriv)
	while True:
		u = PRF.randint(2**(T-1), 2**T)
		l = getRandomNBitInteger(T1)
		p1 = int_add(u, l)
		if isPrime(p1):
			return p1

def GetPrimes(spub, spriv):
	p1 = GenPrimeWithOracle(spriv, k/2, e)
	while True:
		s0 = getRandomNBitInteger(o - m - 1)
		s = int_add(s0, spub)
		t = pi_sit_x(o, s)
		r2 = getRandomNBitInteger(k-o)
		nc = int_add(t, r2)
		q1 = nc / p1
		if isPrime(q1):
			return (p1, q1)

def main():
	verify()
	usage = """
01010111 01100101 01101100 01100011 01101111 01101101  
01110100 01101111 00110010 00110000 00110001 00110110 
01001000 01000011 01010100 01000110 01010010 01010011 01000001 
01000100 01100101 01100011 01101111 01100100 01100101 
01010011 01111001 01110011 01110100 01100101 01101101 
	"""
	print usage
	print "This is a RSA Decryption System"
	print "Please enter Your team token: "
	try:
		token = raw_input()
		flag = get_flag(token)
		assert len(flag) == 38
	except:
		print "Token error!"
		m_exit(-1)

	spub, spriv = get_pkey()
	# Generation p, q
	p, q = GetPrimes(spub, spriv)
	n = p * q
	phi_n = (p-1)*(q-1)
	d = invmod(e, phi_n)
	while True:
		e2 = random.randint(0x1000, 0x10000)
		if gcd(e2, phi_n) == 1:
			break

	print "In this Game, Your public key:"
	print "n: ", hex(n)
	print "e: ", hex(e)
	print "e2: ", hex(e2)
	flag = bytes_to_long(flag)
	enc_flag = pow(flag, e2, n)
	print "Your flag is: ", hex(enc_flag)
	print "============Start Games============"
	print "Please enter your cipher: "
	while True:
		s = raw_input()
		try:
			c = int(s)
		except:
			m_exit(-1)
		m = pow(c, d, n)
		print "Your Plaintext is: ", hex(m)
		time.sleep(1)

if __name__ == '__main__':
	main()
