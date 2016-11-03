#!/usr/bin/env python
# -*- coding:utf-8 -*-

import hashlib
import time
import base64
import sys
# import key


def authcode(string, key=""):
	ck_len = 4

	key = hashlib.md5(key).hexdigest()
	keya = hashlib.md5(key[:16]).hexdigest()
	keyb = hashlib.md5(key[16:]).hexdigest()
	keyc = hashlib.md5(str(time.time())).hexdigest()[-ck_len:]

	cryptkey = keya + hashlib.md5(keya + keyc).hexdigest()
	key_len = len(cryptkey)

	sign = string + keyb
	string = hashlib.md5(sign).hexdigest()[:16] + string
	string_len = len(string)

	result = ""
	box = range(0, 256)
	rndkey = []

	for i in range(0, 255):
		rndkey.append(ord(cryptkey[i % key_len]))

	j = 0
	for i in range(0, 255):
		j = (j + box[i] + rndkey[i]) % 256
		tmp = box[i]
		box[i] = box[j]
		box[j] = tmp

	a = j = 0
	for i in range(string_len):
		a = (a + 1) % 256
		j = (j + box[a]) % 256
		tmp = box[a]
		box[a] = box[j]
		box[j] = tmp
		result += chr(ord(string[i]) ^ (box[(box[a] + box[j]) % 256]))

	return keyc + base64.b64encode(result)

if __name__ == '__main__':
	print "Please enter your string: "
	sys.stdout.flush()
	strings = raw_input()
	enc = authcode(strings, key.key)
	print "The cipher is: " + enc
