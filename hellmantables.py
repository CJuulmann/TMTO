import math
import array
import matplotlib.pyplot as plt
from Crypto.Cipher import AES
from Crypto import Random


# ------------------------------------
# Success probability Hellman tables
# ------------------------------------
def probsuccess():
    x = []
    y = []

    l = 2 ** 8

    for m in range(1, 1000):
        t = 2 ** 16 / m
        ph = 1 - math.exp(
            -math.sqrt((2 * m * l ** 2) / (2 ** 24)) * (math.exp(math.sqrt((2 * m * t ** 2) / (2 ** 24))) - 1) / (
                    math.exp(math.sqrt((2 * m * t ** 2) / (2 ** 24))) + 1))
        x.append(m)
        y.append(ph*(2**24))

    plt.plot(x, y)
    plt.xlabel('m')
    plt.ylabel('Theoretical coverage (PH*2^l)')
    plt.show()


# probsuccess()


# ----------------------------------
# Enc function f using AES-128
# ----------------------------------
def f(p, k):
    aes = AES.new(k, AES.MODE_ECB)
    c = aes.encrypt(p)
    c = c[:3]                     # return as byte string
    return c


# -------------------------
# Reduction function fi
# -------------------------
def fi(p, k, i):
    c = f(p,k)
    c2 = int.from_bytes(c, byteorder='big')     # convert to int
    ciph = (c2 + i) % (2 ** 24)                 # reduce mod 2^24 (key-space)

    ciph = ciph.to_bytes(3, byteorder='big')    # slice first 3 bytes (24 bits)
    return ciph


# ---------------------------------------------
# Hellman tables
# + restrictions: l=2**8 and mtl=2**24 => t=2**16/m
# + investigate coverage by different m values
#
# Thus,
# 256 tables with each m*t computed keys where
# fi : [0, 2^24-1] -> [0, 2^24-1]
# ---------------------------------------------
cov = 0


def hellman_tables(m):
    t = int((2 ** 16) / m)
    fixed_p = '0123456789abcdef'

    # Allocate start and end points of each table: m*256 (m rows and 256 columns)
    start_points = []
    end_points = []

    for i in range(256):
        for p in range(m):
            # generate random key for every chain that we denote m
            k = Random.new().read(16)
            c = ''
            for q in range(t):
                if q == 0:
                    # if first link in chain then feed rand key and save fi output as start point for this chain
                    # register computed key for coverage check
                    c = fi(fixed_p, k, i)
                    start_points.append(c)

                    # convert byte string to int for key-space indexing
                    ci = int.from_bytes(c, byteorder='big')
                    keys[ci] = 1

                    # next cipher in chain as key (expand from 3 to 16 bytes w. 0 trailing)
                    c = c[::-1].zfill(16)[::-1]

                elif q == (t - 1):
                    # if last link in chain then feed prev fi output as key and save end point for this chain
                    # register computed key for coverage check
                    c = fi(fixed_p, c, i)
                    end_points.append(c)
                    ci = int.from_bytes(c, byteorder='big')
                    keys[ci] = 1
                    c = c[::-1].zfill(16)[::-1]
                else:
                    # # if middle of chain then feed prev fi output as key and do not save
                    # register computed key for coverage check
                    c = fi(fixed_p, c, i)
                    ci = int.from_bytes(c, byteorder='big')
                    keys[ci] = 1
                    c = c[::-1].zfill(16)[::-1]
        print("coverage for ", i, sum(keys))

    # Compute coverage of keys found
    inv_cov = sum(keys)

    return inv_cov


# ------------------------------------------------------------
# Compute Hellman tables for various values of m (chain sizes)
# + tables, l = 256
# + different reduction function, fi, for each table
# -----------------------------------------------------------
x = []
y = []

chains = [5, 10, 50, 100, 500, 1000]
for j in range(6):
    m = chains[j]

    # Allocate key coverage array and var for this investigation of m
    keys = [0] * (2 ** 24)
    cov = 0
    print('m =', m)

    cov = hellman_tables(m)

    x.append(m)
    y.append(cov)

plt.plot(x, y)
plt.xlabel('Investigated m')
plt.ylabel('Investigated coverage')
plt.show()


