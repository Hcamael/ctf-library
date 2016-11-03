#!/usr/bin/env python
# -*- coding:utf-8 -*-

from optparse import OptionParser
import struct
import ctypes

def ROTL32(x, r):
	x, r = int(x), int(r)
	return (x << r) ^ (x >> (32 - r))

class SHA1Attack():
	"""
	SHA1 Length extend attack by Hcamael
	s = sha1(mac+m)
	if we know s, we can calculate sha1(mac+m+padding+msg)
	"""
	def __init__(self, options):
		self.hash_ = [0, 0, 0, 0, 0]
		for x in xrange(0, 40, 8):
			self.hash_[x/8] = int(options.signal[x:x+8], 16)
		self.length_ = len(options.extend) + ((options.macl + len(options.origin)) / 64 + 1) * 64
		print self.length_
		self.str_to_block(options.extend)
		self.block = self.padding()

	def padding(self):
		message = []
		for x in xrange(16):
			message.append(0)
		for x in xrange(16):
			tmp = struct.pack("I", self.block[x])
			message[x] = int(tmp.encode('hex'), 16)

		index = (self.length_ & 63) >> 2
		shift = (self.length_ & 3) * 8
		message[index] &= ~(0xFFFFFFFF << shift)
		message[index] ^= 0x80 << shift
		index += 1

		if index > 14:
			while index < 16:
				message[index] = 0
				index += 1
			# 进行大小端转换
			for x in xrange(16):
				tmp = struct.pack("I", message[x])
				message[x] = int(tmp.encode('hex'), 16)
			self.block = message
			self.sha1_process()
			index = 0

		while index < 14:
			message[index] = 0
			index += 1

		data_len = self.length_ << 3
		data_len = int(struct.pack("L", data_len).encode("hex"), 16)
		message[14] = data_len & 0x00000000FFFFFFFF
		message[15] = (data_len & 0xFFFFFFFF00000000) >> 32
		# 进行大小端转换
		for x in xrange(16):
			tmp = struct.pack("I", message[x])
			message[x] = int(tmp.encode('hex'), 16)
		return message

	def str_to_block(self, msg):
		self.block = []
		msg += (64 - self.length_%64) * '\x00'
		for i in xrange(0,  64, 4):
			tmp = msg[i: i + 4]
			tmp = int(tmp.encode('hex') or '0', 16)
			self.block.append(tmp)

	def calculate(self):
		self.sha1_process()
		for x in xrange(5):
			self.hash_[x] = ctypes.c_uint32(self.hash_[x])
		result = ""
		for x in self.hash_:
			result += "{:0>8}".format(hex(x.value)[2:-1])
		return result

	def sha1_process(self):
		wblock = []
		for x in xrange(80):
			wblock.append(0)

		for x in xrange(16):
			wblock[x] = self.block[x]

		for x in xrange(16, 80):
			wblock[x] = ROTL32(wblock[x - 3] ^ wblock[x - 8] ^ wblock[x - 14] ^ wblock[x - 16], 1) & 0xFFFFFFFF

		a = self.hash_[0]
		b = self.hash_[1]
		c = self.hash_[2]
		d = self.hash_[3]
		e = self.hash_[4]

		for x in xrange(20):

			temp = ROTL32(a, 5) + (((c ^ d) & b) ^ d) + e + wblock[x] + 0x5A827999
			temp &= 0xFFFFFFFF
			e = d
			d = c
			c = ROTL32(b, 30) & 0xFFFFFFFF
			b = a
			a = temp

		for x in xrange(20, 40):
			temp = ROTL32(a, 5) + (b ^ c ^ d) + e + wblock[x] + 0x6ED9EBA1
			temp &= 0xFFFFFFFF
			e = d
			d = c
			c = ROTL32(b, 30) & 0xFFFFFFFF
			b = a
			a = temp

		for x in xrange(40, 60):
			temp = ROTL32(a, 5) + ((b & c) | (b & d) | (c & d)) + e + wblock[x] + 0x8F1BBCDC
			temp &= 0xFFFFFFFF
			e = d
			d = c
			c = ROTL32(b, 30) & 0xFFFFFFFF
			b = a
			a = temp

		for x in xrange(60, 80):
			temp = ROTL32(a, 5) + (b ^ c ^ d) + e + wblock[x] + 0xCA62C1D6
			temp &= 0xFFFFFFFF
			e = d
			d = c
			c = ROTL32(b, 30) & 0xFFFFFFFF
			b = a
			a = temp

		self.hash_[0] += a
		self.hash_[1] += b
		self.hash_[2] += c
		self.hash_[3] += d
		self.hash_[4] += e
		for x in xrange(5):
			self.hash_[x] &= 0xFFFFFFFF

def add_parse():
	parser = OptionParser()
	parser.add_option(
		"--macl",
		dest="macl",
		type="int",
		help="Please enter the length of mac")
	parser.add_option(
		"--o",
		dest="origin",
		help="sha1(mac+origin), Please enter the origin")
	parser.add_option(
		"--sign",
		dest="signal",
		help="signal=sha1(mac+origin), Please enter the signal")
	parser.add_option(
		"--e",
		dest="extend",
		help="Please enter the extend value")
	return parser

def main():
	parser = add_parse()
	(options, args) = parser.parse_args()
	if not (options.macl and options.origin and options.signal and options.extend):
		parser.parse_args(['sha1-length-extend-attack.py', '-h'])
		exit(-1)
	o_data_length = options.macl + len(options.origin)
	p = 64 - 8 - 1 - o_data_length
	n = 2
	while p < 0:
		p = 64 * n - 8 - 1 - o_data_length
		n += 1
	o_data_length *= 8
	o_data_length = "{:0>16}".format(hex(o_data_length)[2:])
	data_l = ""
	for x in xrange(0, 16, 2):
		data_l += "\\x" + o_data_length[x:x+2]
	cal = SHA1Attack(options)
	result = cal.calculate()
	print "+---------------------------+"
	print "|         Result             |"
	print "+---------------------------+"
	print "Origin signal: " + options.signal
	print "New signal: " + result
	print "New msg: " + "(" + str(options.macl) + " bytes unknow MAC) + " + options.origin + "\\x80" + "\\x00" * p + data_l + options.extend

if __name__ == '__main__':
	main()