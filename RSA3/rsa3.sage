from sage3 import get_p4

n = 0xf7a8a487bc5c8127ac30cfbfc08e042580f359edce3db416b8a9abcb0e8dcac5404bb0eea3076966a78bb8e726e6fea79d305cc7c2cddb3dd2578a64b5591df1c9716878f35f1967398861cb368886b60c6d0c2984be3ead8dcdd80d68bb094805068b5d157c16d2b56cf0c3f06797b07bf3a7ab2a5099762958feaf72a212a63c74a4fb7da4092e6a91e72bf74ee961b995545891290c50cb28151b540efdedef9d4cc1c104758050c21dda8be8310fc7e005a08cedbcc8500fe0f9fdaa044e7cb07387060358add1d82521b5f8697b6a8ca2bd19a363bae7558e94404a1c4b82ee98878f9dff0e21030e020c698778aa645001f4c7726d3ac04720295975c9
pbits = 1024

g_p = get_p4()
while True:
    p4 = g_p.next()
    # p4 = 0x81a722c9fc2b2ed061fdab737e3893506eae71ca6415fce14c0f9a45f8e2300711119fa0a5135a053e654fead010b96e987841e47db586a55e3d4494613aa0cc4e4ab59fc6a958b5
    kbits = pbits - 576
    p4 = p4 << kbits

    PR.<x> = PolynomialRing(Zmod(n))
    f = x + p4
    x0 = f.small_roots(X=2^kbits, beta=0.4)
    if len(x0) == 0:
        continue
    print "x: %s" %hex(int(x0[0]))

    p = p4+x0[0]
    print "p: ", hex(int(p))
    assert n % p == 0
    q = n/int(p)

    print "q: ", hex(int(q))
    print "p4: ", hex(p4)
    break