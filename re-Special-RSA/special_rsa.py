import os, sys
from key import k, random_r
import msgpack

N = 23927411014020695772934916764953661641310148480977056645255098192491740356525240675906285700516357578929940114553700976167969964364149615226568689224228028461686617293534115788779955597877965044570493457567420874741357186596425753667455266870402154552439899664446413632716747644854897551940777512522044907132864905644212655387223302410896871080751768224091760934209917984213585513510597619708797688705876805464880105797829380326559399723048092175492203894468752718008631464599810632513162129223356467602508095356584405555329096159917957389834381018137378015593755767450675441331998683799788355179363368220408879117131L

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    assert g == 1
    return x % m

def pad_even(x):
    return ('', '0')[len(x)%2] + x

def encrypt(ms, k):
    out = [] 
    for i in range(0, len(ms), 256):
        m = ms[i:i+256]
        m = int(m.encode('hex'), 16)
        r = random_r()
        r_s = pad_even(format(r, 'x')).decode('hex')
        assert m < N
        c = (pow(k, r, N) * m) % N
        c_s = pad_even(format(c, 'x')).decode('hex')
        out.append((r_s, c_s))
    return msgpack.packb(out)

def decrypt(c, k):
    out = ''
    for r_s, c_s in msgpack.unpackb(c):
        r = int(r_s.encode('hex'), 16)
        c = int(c_s.encode('hex'), 16)
        k_inv = modinv(k, N)
        out += pad_even(format(pow(k_inv, r, N) * c % N, 'x')).decode('hex')
    return out

if __name__ == '__main__':
    if len(sys.argv) < 4 or sys.argv[1] not in ('enc', 'dec'):
        print 'usage: %s enc|dec input.file output.file' % sys.argv[0]
        sys.exit()

    with open(sys.argv[3], 'w') as f:
        if sys.argv[1] == 'enc':
            f.write(encrypt(open(sys.argv[2]).read(), k))
        elif sys.argv[1] == 'dec':
            f.write(decrypt(open(sys.argv[2]).read(), k))