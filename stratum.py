import threading,time

import pools

import logging
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)



from src import ScryptProxy
#from src import Sha256Proxy
#from src import X11Proxy
#from src import EthashProxy

class Stratum(threading.Thread):
	def __init__(self):
		self.pools=pools.pools
		self.isAlive=True

		self.stratums={}
		self.stratums["scrypt"]=[ScryptProxy.ScryptStratum(self.pools["scrypt"][0], 3333, nonceBytes=1),self.pools["scrypt"][0]]


		threading.Thread.__init__(self)
		self.start()

	def shutdown(self):
		self.isAlive = False

	def update(self):
		for algorithm in self.pools:
			if algorithm not in self.stratums:
				continue

			maximum = 0
			maximumProfitability = -1
			x=0
			for pool in self.pools[algorithm]:
				method = pool["profitability"]
				profitability = method()
				if profitability>maximumProfitability:
					maximum = x
					maximumProfitability = profitability
				x+=1

			if self.stratums[algorithm][1] != self.pools[algorithm][maximum]:
				if maximumProfitability>self.stratums[algorithm][1]["profitability"]()*1.03:
					if self.stratums[algorithm][0].readyToChange():
						self.stratums[algorithm][0].changePool(self.pools[algorithm][maximum])
						self.stratums[algorithm][1] = self.pools[algorithm][maximum]
						logging.info("new best pool for {}: {}".format(algorithm,self.pools[algorithm][maximum]["url"]))

	def run(self):
		while self.isAlive:
			try:
				self.update()
				time.sleep(0.03)
			except:
				raise
				self.isAlive = False


	def getShares(self):
		ret = {}
		for algo in self.stratums:
			shares = self.stratums[algo][0].getShares()
			ret[algo]={}
			for worker in shares:
				if worker not in ret[algo]:
					ret[algo][worker]=shares[worker]
				else:
					ret[algo][worker][0]+=shares[worker][0]
					ret[algo][worker][1]+=shares[worker][1]
		return ret

	def killOrder(self):
		usernames = []
		for proxy in self.stratums["scrypt"][0].proxies:
			for miner in proxy.miners:
				if miner.username in usernames:
					miner.kill()
				else:
					usernames.append(miner.username)




stratum = None


def start():
	global stratum
	stratum = Stratum()
