
from math import ceil, sqrt, log

def isqrt(x):
    return int(sqrt(x)) + 1

def newton(n):
    if n == 0:
        return 0
    y = 0
    x = 2
    while y != x and y != x + 1:
        y = x
        x = (x + n // x) // 2
    return x + 1

def newton_k(k, n):
    if n == 0:
        return 0
    x = 16
    for _ in range(k):
        x = (x + n // x) // 2
    return x + 1

def newton4(n):
    return newton_k(16, n)

def memory_cost(w):
    return 3 * w + w*w // 512

def inv1(g):
    return int(-768 + 16 * isqrt(2*g + 2*1152))

def inv2(g):
    return int(-768 + 16 * isqrt(2*g + 2*1153))

def inv3(g):
    return int(-768 + isqrt(256*(2*g + 2*1152)))

fns = [inv1, inv3]
isqrt_fns = [isqrt, newton, newton4]

gas_limit = 2**63-1

def test_inv():
    for i in range(1000000000):
        c = memory_cost(i)

        p = False
        data = []
        for f in fns:
            w = f(c)
            e = i - w
            data += [w, e]
            p = p or e != 0

        if p or i % 1000000 == 0:
            bits = int(ceil(log(c) / log(2))) if c != 0 else 0
            print("{} {} {} {}".format(bits, c, i, data))

        if c > gas_limit:
            print("All tested")
            break

def test_isqrt():
    for i in range(2**32, 2**33):
        data = []
        r = int(ceil(sqrt(i)))
        for f in isqrt_fns:
            s = f(i)
            if s != r:
                print("{}({}) = {} != {}".format(f.__name__, i, s, r))
            data.append(f(i))
        # print("{} {} {}".format(i, r, data))

# test_inv()
test_isqrt()
