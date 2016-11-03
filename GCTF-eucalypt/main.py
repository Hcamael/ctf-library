#!/usr/bin/env python
# -*- coding:utf-8 -*-

from flask import Flask
from flask import request
from flask import make_response
from Crypto.Cipher import AES
import json
import os

app = Flask(__name__)

class Signal():
	def __init__(self):
		self.aes_key = '???'
		assert len(self.aes_key) == 16

	def encode(self, obj):
		s = json.dumps(obj)
		iv = os.urandom(16)
		pad = (16 - (len(s) % 16))
		s += chr(pad) * pad
		algo = AES.new(self.aes_key, AES.MODE_CBC, IV=iv)
		crypttext = algo.encrypt(s)
		c = (iv + crypttext).encode('hex')
		return c

	def decode(self, string):
		crypttext = string.decode('hex')
		if len(crypttext) < 16:
			return None
		iv, crypttext = crypttext[:16], crypttext[16:]
		algo = AES.new(self.aes_key, AES.MODE_CBC, IV=iv)
		plaintext = str(algo.decrypt(crypttext))
		pad = ord(plaintext[-1])
		if pad > 16:
			raise ValueError, "pad error - pad is %d" %(pad)
		expected = chr(pad) * pad
		piece = plaintext[-pad:]
		if piece != expected:
			raise ValueError, "padding is corrupted"
		try:
			obj = json.loads(plaintext[:-pad])
		except:
			return None
		return obj

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
		cookie = s.encode(obj)
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
	obj = s.decode(cookie)
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