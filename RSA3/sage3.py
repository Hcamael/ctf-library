import random

spriv = 76515803399948578070392316249460231617205640228540294074078216016927174232385
T = 512 + 64

PRF = random.Random()
PRF.seed(spriv)

def get_p4():
    while True:
        u = PRF.randint(2**(T-1), 2**T)
        yield u
        