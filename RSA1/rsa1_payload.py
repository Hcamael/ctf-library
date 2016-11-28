#! /usr/bin/env python
# -*- coding: utf-8 -*-

from hashlib import sha512
from Crypto.Util.number import long_to_bytes, getPrime, bytes_to_long
from libnum import invmod, gcd
from pwn import process, context, remote
import itertools
import time
import random

fuzzing = "abcdefghijklmnopqrstuvwxyz0123456789QWERTYUIOPASDFGHJKLZXCVBNM"
fuzz = itertools.permutations(fuzzing, 5)
context.log_level = "debug"

def cal_bit(num):
	num = int(num)
	l = len(bin(num))
	return l-2

def isqrt(n):
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    if pow(x, 2) == n:
    	return x
    else:
    	return False

def divide_pq(ed, n):
	# ed = e*d
	k = ed - 1
	while True:
		g = random.randint(3, n-2)
		t = k
		while True:
			if t % 2 != 0:
				break
			t /= 2
			x = pow(g, t, n)
			if x > 1 and gcd(x-1, n) > 1:
				p = gcd(x-1, n)
				return (p, n/p)

def pi_b(x):
	bt = 536380958350616057242691418634880594502192106332317228051967064327642091297687630174183636288378234177476435270519631690543765125295554448698898712393467267006465045949611180821007306678935181142803069337672948471202242891010188677287454504933695082327796243976863378333980923047411230913909715527759877351702062345876337256220760223926254773346698839492268265110546383782370744599490250832085044856878026833181982756791595730336514399767134613980006467147592898197961789187070786602534602178082726728869941829230655559180178594489856595304902790182697751195581218334712892008282605180395912026326384913562290014629187579128041030500771670510157597682826798117937852656884106597180126028398398087318119586692935386069677459788971114075941533740462978961436933215446347246886948166247617422293043364968298176007659058279518552847235689217185712791081965260495815179909242072310545078116020998113413517429654328367707069941427368374644442366092232916196726067387582032505389946398237261580350780769275427857010543262176468343294217258086275244086292475394366278211528621216522312552812343261375050388129743012932727654986046774759567950981007877856194574274373776538888953502272879816420369255752871177234736347325263320696917012616273L
	return invmod(x, bt)

def con_fra(a, b):
	r = []
	while True:
		if a == 1:
			break
		tmp = a/b
		if tmp != 0:
			r.append(tmp)
		a, b = b, (a-tmp*b)
	return r

def wiener_attack(e, n):
	cf = con_fra(e, n)
	for x in xrange(len(cf)):
		k, d = 0, 1
		while x >= 0:
			k, d = d, d*cf[x] + k
			x -= 1
		# print "k: %s\nd: %s\n" %(k, d)
		phi_n = (e*d - 1)/k
		B = n - phi_n + 1
		C = n
		dt = pow(B, 2) - 4*C    # b^2 - 4*a*c
		if dt >= 0 and isqrt(dt) and (B+isqrt(dt)) % 2 == 0:
			print "phi_n: ", hex(phi_n)
			return phi_n
	print "wiener attack fail!"

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
	r = remote("115.159.191.193", 12000)
	# r = process("rsa1.py")
	verify(r)
	r.readuntil("token: ")
	token = "81755de89626aba8db7de4c93e658b68wBJekMIo"
	r.sendline(token)

	r.readuntil("n: ")
	n = r.readline().strip()
	n = int(n[2:-1], 16)

	r.readuntil("e: ")
	e = r.readline().strip()
	e = int(e[2:-1], 16)

	r.readuntil("is: ")
	enc_flag = r.readline().strip()
	enc_flag = int(enc_flag[2:-1], 16)

	print "We know:"
	print "n: ", hex(n)
	print "e: ", hex(e)
	print "flag: ", hex(enc_flag)

	print "=======Start Attack======"
	t = pi_b(e)
	print "get t = ", hex(t)
	phi_n = wiener_attack(t, n)
	try:
		u = invmod(t, phi_n)
	except:
		return False
	print "get u = ", hex(u)
	qq, pp = divide_pq(u*t, n)
	print "get p = ", hex(pp)
	print "get q = ", hex(qq)
	d = invmod(e, (qq-1)*(pp-1))
	print "get d = ", hex(d)
	flag = pow(enc_flag, d, n)
	print "get flag: ", long_to_bytes(flag)

if __name__ == '__main__':
	main()