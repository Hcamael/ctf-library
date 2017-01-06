#! /usr/bin/env python
# -*- coding: utf-8 -*-

from binascii import unhexlify
from Crypto.Util.number import str2long
from sha1 import SHA1
import struct
import sys

L = 600

def hx(v):
	return "{:0>8}".format(hex(v)[2:])

def main(random):
	h = struct.unpack("IIIII", random[L-40:L-20])
	randhasher = random[L-40:L-20]+random[:44]
	sha1_hash = SHA1()
	for x in xrange(5):
		sha1_hash.hash_[x] = h[x]
	res = sha1_hash.sha1(randhasher, len(randhasher))
	(v0, v1, v2, v3, v4) = struct.unpack("<IIIII", unhexlify(res))
	outstr =  hx(v0) + hx(v1) + hx(v2) + hx(v3) + hx(v4)
	return outstr
	

if __name__ == '__main__':
	'''
	本脚本为CVE-2016-6313检测脚本
	使用gcrypto生成600byte随机数
	输入为600/580byte的十六进制形式
	'''

	if len(sys.argv) > 1:
		random = sys.argv[1]
	else:
		exit();
	try:
		random = random.strip().decode('hex')
		assert len(random) >= 580
	except:
		print "error hex"
	outstr = main(random)
	if outstr in sys.argv[1]:
		print "the random can be predicted"
	else:
		print "the predict 20 byte number is: %s" %outstr