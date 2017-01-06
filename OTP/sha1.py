#!/usr/bin/env python
# -*- coding:utf-8 -*-

import ctypes
import struct

def ROTL32(x, r):
    try:
        a = (x << r) ^ (x >> (32 - r))
    except:
        print type(x)
        print type(r)
        exit(-1)
    return a

class SHA1():
    def __init__(self):
        self.length_ = 0
        self.unprocessed_ = 0
        self.hash_ = [
            0x67452301,
            0xefcdab89,
            0x98badcfe,
            0x10325476,
            0xc3d2e1f0
        ]

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

    def str_to_block(self, x):
        self.block = []
        for i in xrange(x, x + 64, 4):
            tmp = self.msg[i: i + 4]
            tmp = int(tmp.encode('hex') or '0', 16)
            self.block.append(tmp)

    def sha1(self, msg, length):
        self.msg = msg
        self.length_ = length
        self.msg += (64 - length % 64) * '\x00'
        self.str_to_block(0)
        self.sha1_process()
        return self.final()

    def final(self):
        for x in xrange(5):
            self.hash_[x] = ctypes.c_uint32(self.hash_[x])
        result = ""
        for x in self.hash_:
            result += "{:0>8}".format(hex(x.value)[2:-1])
        return result

if __name__ == '__main__':
    hash_test = SHA1()
    msg = "a"*64
    print hash_test.sha1(msg, len(msg))