# 16/11/2022
# Created by M-DarkMan

"""
USEGE :
> python3 address.py -a 1rSnXMr63jdCuegJFuidJqWxUPV7AtUf7 -b 24
> python3 address.py -a 13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so -b 66 -r 2048 -c 6
"""

from argparse import ArgumentParser
import multiprocessing as MP
from random import randint
from ice.secp256k1 import (
    b58_decode as b58,
    privatekey_to_h160 as p2h,
    privatekey_loop_h160_sse as loop)
import sys

parser = ArgumentParser(description='It splits the bit range and assigns a random number in each allocated range, searching backwards and forwards by -r.', epilog='https://github.com/geokomplo/')
parser.add_argument("-a", "--address", help = "P2PKH Address", required=True)
parser.add_argument("-b", "--bit", help = "Bit Range (20 - 256)", required=True)
parser.add_argument("-r", "--range", help = "The number or range of steps to search for in the fragmented bit range. | Default : 16384")
parser.add_argument("-c", "--cpu", help = "CPU Count | Default : 4")
if len(sys.argv)==1: parser.print_help(), sys.exit(1)
args = parser.parse_args()
address, bit, RANGE, cpu_count = args.address, int(args.bit), int(args.range) if args.range else 16384, int(args.cpu) if args.cpu else 4
_ = 2**(bit-1)
P = bytes.fromhex(b58(address)[2:-8])

def found(x):
    for i in range(RANGE):
        _p, p_ = x + i, x - i
        T = p2h(0, True, _p) + p2h(0, True, p_)
        if P in T:
            V = hex(_p)[2:] if p2h(0, True, _p) == P else hex(p_)
            print('#'*30 + f'\nPrivate Key : {V}\n' + '#'*30)
            open('found.txt', 'a').write('#'*30 + f'\nPrivate Key : {V}\n' + '#'*30 + '\n')
            return True

def RUN(q, f):
    while not q.is_set():
        M = randint(16, 64)
        B = _ // M
        S = [_ + (B * i) for i in range(M + 1)]
        R = randint(1, S[1] - S[0])
        for I in range(M):
            K = S[I] + R
            T = loop(RANGE, 0, True, K) + loop(RANGE, 0, True, K - RANGE)
            if P in T:
                found(K)
                f.set()
                break

if __name__ == '__main__':
    q, f = MP.Event(), MP.Event()
    for i in range(cpu_count):
        PC = MP.Process(target=RUN, args=(q, f, ))
        PC.start()
    f.wait()
    q.set()
