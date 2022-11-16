# 16/11/2022
# Created by Mr-DarkMan

import multiprocessing as mp
from random import randint
from ice.secp256k1 import (
	scalar_multiplication as SM,
	Fill_in_bloom as BL,
	pub2upub as p2u,
	point_addition as PA,
	point_subtraction as PS,
	check_in_bloom as CB)
import sys

class Proc:
	def __init__(self, quit, foundit, public_key, bit_range, bloom_range, N):
		self.P, self.bit_range, self.bloom_range, self.N = \
			p2u(public_key), bit_range, bloom_range, N
		self.Q = SM(1)
		self.main(quit, foundit)

	def bloom(self):
		p, self.D = [], []
		L = self.bit_range//(2**self.N)
		for i in range(self.bloom_range//2):
			r = randint(1, L)
			R = SM(r)
			pa = PA(self.P, R)
			ps = PS(self.P, R)
			p.append(pa), p.append(ps), self.D.append(r)
		self._bits, self._hashes, self._bf = BL(p, 0.000001)
		del p

	def found(self, x1, x2):
		x = hex(x1)[2:] if SM(x1) == self.P else hex(x2)
		private_key = f'Private Key : {x}'
		open('found.txt', 'a').write(str(private_key) + '\n')
		print('-'*40 + f'\nKEY FOUND = {private_key}\n' + '-'*40)

	def collision(self, K):
		for n in self.D:
			x1, x2 = K - n, K + n
			if SM(x1) == self.P or SM(x2) == self.P:
				self.found(x1, x2)
				return True

	def main(self, quit, foundit):
		self.bloom()
		while not quit.is_set():
			M = randint(2**self.N, 2**(self.N + 1))
			B = self.bit_range // M
			S = [self.bit_range + (B * i) for i in range(M + 1)]
			R = randint(1, S[1] - S[0])
			print(hex(S[0] + R))
			for I in range(M):
				K = S[I] + R
				if CB(SM(K), self._bits, self._hashes, self._bf):
					if self.collision(K):
						foundit.set()
						break

if __name__ == "__main__":
	cpu_count = 4
	bit = 40
	N = 15
	bloom_range = 2**20 // cpu_count
	bit_range = 2**(bit-1)
	public_key = '03a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4'
	quit = mp.Event()
	foundit = mp.Event()
	for i in range(cpu_count):
		pc = mp.Process(target=Proc, args=(quit, foundit, public_key, bit_range, bloom_range, N))
		pc.start()
	foundit.wait()
	quit.set()
