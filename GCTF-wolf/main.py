#!/usr/bin/env python
# -*- coding:utf-8 -*-

from flask import Flask
from flask import request
from flask import make_response
from Crypto.Hash import SHA
from Crypto.Cipher import AES
import json
import os
import urllib
import urlparse

app = Flask(__name__)

class Signal():
	def __init__(self):
		self.aes_key = '??'
		self.mac_key = "??"
		assert len(self.aes_key) == 16
		assert len(self.mac_key) == 32

	def encode(self, s):
		iv = os.urandom(16)
		pad = (16 - (len(s) % 16))
		s += chr(pad) * pad
		algo = AES.new(self.aes_key, AES.MODE_CBC, IV=iv)
		crypttext = algo.encrypt(s)
		return (iv + crypttext)

	def decode(self, string):
		if len(string) < 16:
			return ValueError, "bad string"
		iv, string = string[:16], string[16:]
		algo = AES.new(self.aes_key, AES.MODE_CBC, IV=iv)
		plaintext = str(algo.decrypt(string))
		pad = ord(plaintext[-1])
		if pad > 16:
			raise ValueError, "pad error - pad is %d" %(pad)
		expected = chr(pad) * pad
		piece = plaintext[-pad:]
		if piece != expected:
			raise ValueError, "padding is corrupted"
		raw = plaintext[:-pad]
		return raw

	def make(self, dct):
		tcd = urllib.urlencode(dct)
		h = SHA.new()
		h.update(self.mac_key)
		h.update(tcd)
		s = h.digest()
		coded = self.encode(tcd)
		return s.encode('hex') + "." + coded.encode('hex')

	def unmake(self, st):
		p = st.split(".")
		if len(p) != 2:
			return None

		s = self.decode(p[1].decode('hex'))
		if s == None:
			return None
		h = SHA.new()
		h.update(self.mac_key)
		h.update(s)
		f = h.hexdigest()
		print s
		if p[0] != f:
			return None

		kv = urlparse.parse_qsl(s)
		ret ={}
		for k, v in kv:
			ret[k] = v
		return ret

@app.route('/')
def index():
	html = '''
	<a href="/register">Register</a><br />
	<a href="/getflag">GetFlag</a>
	'''
	return html

@app.route('/register', methods=['GET', 'POST'])
def register():
	if request.method == 'GET':
		html = '''
		<form action="" method="POST">
		请输入用户名：<input type="text" name="username">
		<input type="submit">
		</form>
		'''
		return html
	if request.method == 'POST':
		obj = {}
		obj['username'] = request.form['username']
		if obj['username'] == "":
			return "bad username"
		if obj['username'] == 'admin':
			return "can't register admin"
		s = Signal()
		cookie = s.make(obj)
		html = '''
		<script>location.href="/getflag";</script>
		'''
		resp = make_response(html)
		resp.set_cookie('id', cookie)
		return resp

@app.route('/getflag')
def getflag():
	cookie = request.cookies.get('id')
	s = Signal()
	obj = s.unmake(cookie)
	if obj == None or "username" not in obj:
		html = "error cookie"
	else:
		if obj['username'] == 'admin':
			html = "flag"
		else:
			html = "Hi! %s, only admin can get flag" % obj['username']
	return html

if __name__ == '__main__':
	app.run(debug=False, port=8091, host="0.0.0.0", threaded=True)