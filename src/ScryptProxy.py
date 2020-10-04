import threading, socket, json, select, binascii, time, hashlib
import scrypt as scrypt_algo
from . import utils
from . import config

def hexFormat(x,size=2,toHex=True):
	if toHex:
		x=hex(x)[2:]
	return "0"*(size-len(x))+x


class ScryptMiner(threading.Thread):
	def build_merkle_root(coinbase_bin, merkle_branch):
		merkle_root = hashlib.sha256(hashlib.sha256(coinbase_bin).digest()).digest()
		for h in merkle_branch:
			merkle_root = hashlib.sha256(hashlib.sha256(merkle_root + binascii.unhexlify(h)).digest()).digest()
		return merkle_root

	def coinbase_bin(work,nonce2,nonce1):
		ret=work[2]+nonce1+nonce2+work[3]
		return binascii.unhexlify(ret)

	def POW(header_bin):
		pow_hash=scrypt_algo.hash(header_bin, header_bin, 1024, 1, 1, 32)
		return binascii.hexlify(pow_hash[::-1])

	def gettarget(difficulty):
		target=2**208*0xFFFF0000
		target=target//difficulty
		return target


	def __dump(self, res):
		return json.dumps(res).encode()+b"\n"

	def __sendMiner(self, res,newNonce):
		if newNonce:
			self.minerNonce+=1
		self.minerSocket.sendall(self.__dump(res))

	def __receive(self):
		data=self.pendingComs

		BUFF_SIZE = 1024*4 # 4 KiB
		while b"\n" not in data:
			part = self.minerSocket.recv(BUFF_SIZE)
			data += part

		self.pendingComs=data[data.find(b"\n")+1:]

		return data[:data.find(b"\n")+1]

	def __load(self,data):
		return json.loads(data)

	def __init__(self, minerSocket, nonce1, nonce2size, nonce3, shareMethod):
		self.minerSocket = minerSocket
		self.minerNonce = 0
		self.username = None

		self.nonce3 = nonce3
		self.shareMethod = shareMethod

		self.nonce1 = nonce1
		self.nonce2size = nonce2size

		self.difficulty = config.sha256_startdiff

		self.jobs = {}

		self.pendingComs = b""

		self.pendingRequests = {}

		self.pastShares = []

		self.duplicate_shares = []

		self.isAlive = True

		self.extranonceSubscribed=False

		self.ready = False

		self.sendJobs = False

		
		threading.Thread.__init__(self)
		self.start()

	def updateMiner(self):
		if select.select([self.minerSocket],[],[],0)[0] or self.pendingComs:
			self.handleMiner(self.__load(self.__receive()))

	def handleMiner(self, data):
		if "method" not in data:
			if "id" in data and data["id"] in self.pendingRequests:
				method=self.pendingRequests[data["id"]]
				method(data)
		else:
			if data["method"]=="mining.submit":
				self.pastShares.append(time.time())
				self.validateShare(data)
				#self.adjustDifficulty()
				#self.considerKick()

			elif data["method"]=="mining.extranonce.subscribe":
				res={"id":data["id"]}
				res["result"]=True
				res["error"]=None
				self.__sendMiner(res,False)
				self.extranonceSubscribed=True

			elif data["method"]=="mining.authorize":
				self.username = data["params"]
				res={"id":data["id"]}
				res["result"]=True
				res["error"]=None
				self.parseArguments(data["params"][1])
				self.__sendMiner(res,False)
				self.sendDifficulty()

			elif data["method"]=="mining.subscribe":
				res={"id":data["id"]}
				res["result"]=[[["mining.set_difficulty", "1a"], ["mining.notify", "1b"]], self.nonce1, self.nonce2size]
				res["error"]=None
				self.ready = True
				self.__sendMiner(res,False)

			elif data["method"]=="mining.get_transaction":
				res={"id":data["id"]}
				res["result"]=[[]]
				res["error"]=None
				self.__sendMiner(res,False)

	def parseArguments(self, password):
		items=password.split(",")
		for item in items:
			if item[:2]=="d=":
				self.difficulty=int(item[2:])
				if self.difficulty<config.scrypt_mindiff:
					self.difficulty=config.scrypt_mindiff
				if self.difficulty>config.scrypt_maxdiff:
					self.difficulty=config.scrypt_maxdiff
		self.sendJobs=True

	def validateShare(self, data):
		id = data["id"]
		share = data["params"]
		if len(share)!=5:
			res={"id":id}
			res["result"]=False
			res["error"]=[20,"Malformed Share"]
			self.__sendMiner(res,False)
			return 

		if len(share[3])!=8 or len(share[4])!=8:
			res={"id":id}
			res["result"]=False
			res["error"]=[20,"Malformed Share"]
			self.__sendMiner(res,False)
			return 

		if len(share[2])!=self.nonce2size*2:
			res={"id":id}
			res["result"]=False
			res["error"]=[20,"Malformed Share"]
			self.__sendMiner(res,False)
			return 

		if share[1:] in self.duplicate_shares:
			res={"id":id}
			res["result"]=False
			res["error"]=[22,"Duplicate Share"]
			self.__sendMiner(res,False)
			return 

		self.duplicate_shares.append(share[1:])


		username = share[0]
		jobID = share[1]

		if jobID not in self.jobs:
			res={"id":id}
			res["result"]=False
			res["error"]=[21,"Stale Share"]
			self.__sendMiner(res,False)
			return

		work,difficulty=self.jobs[jobID]

		#share[2]=self.nonce3+share[2]
		print(share)

		merkleroot=ScryptMiner.build_merkle_root(ScryptMiner.coinbase_bin(work,share[2],self.nonce1),work[4])
		header1=utils.swap_endian_word(work[5])
		header1+=utils.swap_endian_words(work[1])
		header2=utils.swap_endian_words(share[3])
		header2+=utils.swap_endian_words(work[6])
		header2+=binascii.unhexlify(share[4])[::-1]
		pow=ScryptMiner.POW(header1+merkleroot+header2)

		value=int(pow,16)

		if value>ScryptMiner.gettarget(difficulty):
			res={"id":id}
			res["result"]=False
			res["error"]=[23,"Low-difficulty Share"]
			self.__sendMiner(res,False)
			return 

		res={"id":id}
		res["result"]=True
		res["error"]=None
		self.__sendMiner(res,False)
		self.shareMethod(username, share, difficulty, value, True)
		return




	def sendDifficulty(self):
		res={"id":None}
		res["method"]="mining.set_difficulty"
		res["params"]=[self.difficulty]
		self.__sendMiner(res,False)

	def adjustDifficulty(self):
		for i in self.pastShares.copy():
			if i+60*5<time.time():
				self.pastShares.remove(i)
		if len(self.pastShares)>40:
			self.difficulty*=2
			self.sendDifficulty()
			self.pastShares=[]
		elif len(self.pastShares)<10:
			if self.difficulty//2>config.scrypt_mindiff:
				self.difficulty//=2
				self.sendDifficulty()
				self.pastShares=[]



	def run(self):
		while self.isAlive:
			try:
				self.updateMiner()
				time.sleep(0.03)
			except:
				self.isAlive = False
		self.kill()

	def kill(self):
		try:
			self.minerSocket.close()
		except:
			pass
		self.isAlive=False

	def newJob(self, job):
		#print(job)
		job[-2]=hex(int(job[-2],16)+int(self.nonce3,16)*1)[2:]

		z=0
		while not self.sendJobs and z<50:
			time.sleep(0.2)
			z+=1
		if z==50:
			print("not ready")
			self.kill()
			return
		if job[-1]:
			self.jobs={}
		self.jobs[job[0]]=(job,self.difficulty)
		req= {}
		req["id"]=None
		req["method"]="mining.notify"
		req["params"]=job
		x=0
		while not self.ready and x<50:
			time.sleep(0.1)
			x+=1
		if self.ready:
			self.__sendMiner(req,False)
		else:
			print("not ready")
			self.kill()

	def newExtranonce(self,nonce1,nonce2size):
		self.firstJob = True
		self.nonce1 = nonce1
		self.nonce2size = nonce2size
		if self.extranonceSubscribed:
			req={}
			req["id"]=None
			req["method"]="mining.set_extranonce"
			req["params"]=[self.nonce1, self.nonce2size]
			self.__sendMiner(req,True)
		else:
			req={}
			req["id"]=None
			req["method"]="client.reconnect"
			req["params"]=[]
			self.__sendMiner(req,True)
			self.kill()






class ScryptProxy(threading.Thread):
	def __dump(self, res):
		return json.dumps(res).encode()+b"\n"

	def __sendPool(self, res,newNonce):
		if newNonce:
			self.poolNonce+=1
		self.poolSocket.sendall(self.__dump(res))

	def __receive(self):
		data=self.pendingComs

		BUFF_SIZE = 1024*4 # 4 KiB
		while b"\n" not in data:
			part = self.poolSocket.recv(BUFF_SIZE)
			data += part

		self.pendingComs=data[data.find(b"\n")+1:]

		return data[:data.find(b"\n")+1]

	def __load(self,data):
		return json.loads(data)

	def __init__(self, pool, nonceBytes=1):
		self.pool = pool

		self.address = (pool["url"],pool["port"])
		self.username = pool["username"]
		self.password = pool["password"] 

		self.userAgent = "profitMiner/0.1"

		self.nonceBytes=nonceBytes

		self.miners = []
		self.nonces = [hexFormat(i,2*nonceBytes) for i in range(2**(8*self.nonceBytes))][50:]

		self.firstJob=True
		self.poolSocket = None
		self.poolNonce = 0

		self.shares = {}

		self.subscribed = False
		self.authorized = False

		self.difficulty = None
		self.nonce1 = None
		self.nonce2size = None
		self.jobs = {}

		self.pendingComs = b""

		self.pendingRequests = {}

		self.isAlive = True

		self.initialize()

		threading.Thread.__init__(self)
		self.start()


	

	def initialize(self):
		self.poolSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.poolSocket.connect(self.address)
		req={"id":self.poolNonce}
		req["method"]="mining.subscribe"
		req["params"]=[self.userAgent]
		self.pendingRequests[self.poolNonce]=self.checkSubscribed
		self.__sendPool(req,True)

		while not self.subscribed:
			self.handlePool(self.__load(self.__receive()))

		req={"id":self.poolNonce}
		req["method"]="mining.authorize"
		req["params"]=[self.username,self.password]
		self.pendingRequests[self.poolNonce]=self.checkAutherized
		self.__sendPool(req,True)

		while not self.authorized:
			self.handlePool(self.__load(self.__receive()))

		res={"id":self.poolNonce}
		res["method"]="mining.extranonce.subscribe"
		res["params"]=[]
		self.pendingRequests[self.poolNonce]=self.empty
		self.__sendPool(res,True)
		self.poolNonce+=1

		while not self.jobs:
			self.handlePool(self.__load(self.__receive()))

	def handlePool(self, data):
		if "method" not in data:
			if "id" in data and data["id"] in self.pendingRequests:
				method=self.pendingRequests[data["id"]]
				method(data)
			return

		else:
			if data["method"]=="client.reconnect":
				self.clearPool()
				self.initialize()
				self.newExtranonce()

			elif data["method"]=="mining.set_extranonce":
				self.nonce1=data["params"][0]
				self.nonce2size=data["params"][1]
				self.newExtranonce()

			elif data["method"]=="mining.set_difficulty":
				self.difficulty=data["params"][0]
				if self.difficulty<2**17:
					self.changePool(self.pool)

			elif data["method"]=="client.get_version":
				res={"id":data["id"]}
				res["result"]=[self.userAgent]
				res["error"]=None
				self.__sendPool(res,False)

			elif data["method"]=="mining.notify":
				self.newJob(data["params"])

			else:
				pass

	def newShare(self, username, submit, targetDifficulty, value, valid):
		if username not in self.shares:
			self.shares[username]=[0,0]

		if valid:
			self.shares[username][0]+=targetDifficulty
		else:
			self.shares[username][1]+=targetDifficulty

		submit[0]=self.username
		jobID = submit[1]
		if jobID in self.jobs:
			work,difficulty=self.jobs[jobID]
		else:
			return

		if value<ScryptMiner.gettarget(difficulty):
			res={"id":self.poolNonce}
			res["method"]="mining.submit"
			res["params"]=submit
			self.pendingRequests[self.poolNonce]=self.empty
			self.__sendPool(res,True)
			return


			

	def checkSubscribed(self,res):
		self.subscribed = True

		self.nonce1 = res["result"][1]
		self.nonce2size = res["result"][2]
		self.newExtranonce()

	def checkAutherized(self,res):
		if res["result"]:
			self.authorized=True
		else:
			raise ValueError("Failed authorize")

	def empty(self,res):
		return

	def newExtranonce(self):
		for miner in self.miners:
			miner.newExtranonce(self.nonce1,self.nonce2size-self.nonceBytes)

	def newJob(self,job):
		if self.firstJob:
			job[-1]=True
		for miner in self.miners:
			miner.newJob(job)
		if job[-1]:
			self.jobs={}
		self.jobs[job[0]]=(job,self.difficulty)
		self.firstJob=False

	def forceNewJob(self):
		job=self.jobs[list(self.jobs.keys())[0]][0]
		job[-1]=True
		for miner in self.miners:
			miner.newJob(job)





	

	def clearPool(self):
		self.firstJob=True
		self.poolSocket = None
		self.poolNonce = 0

		self.subscribed = False
		self.authorized = False

		self.difficulty = None
		self.nonce1 = None
		self.nonce2size = None
		self.jobs = {}

		self.pendingComs = b""

		self.pendingRequests = {}

		self.isAlive = True

	def changePool(self,pool):
		self.pool = pool

		self.address = (pool["url"],pool["port"])
		self.username = pool["username"]
		self.password = pool["password"]
		self.clearPool()
		self.initialize()
		self.newExtranonce()
		self.forceNewJob()

	def addMiner(self,socket):
		if self.nonceBytes==0:
			nonce3=""
		else:
			nonce3=self.nonces.pop(0)
		miner = ScryptMiner(socket,self.nonce1,self.nonce2size,nonce3,self.newShare)
		self.miners.append(miner)
		for job in self.jobs:
			miner.newJob(self.jobs[job][0])
		return True

	def isFull(self):
		if self.nonceBytes==0:
			return True
		if len(self.nonces)==0:
			return True
		return False

	def isAlive(self):
		return True

	def kill(self):
		for miner in self.miners:
			miner.kill()
		self.isAlive = False

	def getShares(self):
		c = self.shares
		self.shares = {}
		return c

	def updatePool(self):
		if select.select([self.poolSocket],[],[],0)[0] or self.pendingComs:
			self.handlePool(self.__load(self.__receive()))

	def minersAlive(self):
		for miner in self.miners.copy():
			if not miner.isAlive:
				self.miners.remove(miner)

	def run(self):
		while self.isAlive:
			try:
				self.minersAlive()
				self.updatePool()
				time.sleep(0.03)
			except:
				self.isAlive = False
		self.kill()


class ScryptStratum(threading.Thread):
	def __init__(self, pool, port , nonceBytes=1):
		self.lastChange = 0

		self.currentPool = pool
		self.port = port
		self.nonceBytes = nonceBytes

		self.proxies = []

		self.stratumSocket = None

		self.initialize()

		self.isAlive=True
		self._shutdown = False

		threading.Thread.__init__(self)
		self.start()

	def initialize(self):
		self.stratumSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.stratumSocket.bind(("0.0.0.0",self.port))
		self.stratumSocket.listen(1)


	def readyToChange(self):
		if self.lastChange+config.scrypt_changeTime<time.time():
			return True
		return False

	



	def kill(self):
		for proxy in self.proxies:
			proxy.kill()
		try:
			pass
			#self.stratumSocket.close()
		except:
			pass
		#self.isAlive = False

	def proxiesAlive(self):
		for proxy in self.proxies.copy():
			if not proxy.isAlive:
				self.proxies.remove(proxy)

	def updateStratum(self):
		if select.select([self.stratumSocket],[],[],0)[0]:
			c,_ = self.stratumSocket.accept()
			for proxy in self.proxies:
				if not proxy.isFull():
					proxy.addMiner(c)
					return
			proxy = ScryptProxy(self.currentPool, self.nonceBytes)
			self.proxies.append(proxy)
			proxy.addMiner(c)
			return

	def changePool(self, pool):
		self.currentPool = pool
		for proxy in self.proxies:
			proxy.changePool(pool)
		self.lastChange = time.time()

	def shutdown(self):
		self._shutdown = True
		self.isAlive = False

	def getShares(self):
		ret = {}
		for proxy in self.proxies:
			shares = proxy.getShares()
			for worker in shares:
				if worker not in ret:
					ret[worker]=shares[worker]
				else:
					ret[worker][0]+=shares[worker][0]
					ret[worker][1]+=shares[worker][1]
		return ret

	def restart(self):
		self.stratumSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.stratumSocket.bind(("0.0.0.0",self.port))
		self.stratumSocket.listen(1)

	def run(self):
		while not self._shutdown:
			while self.isAlive:
				try:
					self.proxiesAlive()
					self.updateStratum()
					time.sleep(0.03)
				except:
					pass
					#self.isAlive = False
			self.kill()
			if not self._shutdown:
				pass
				#self.restart()
			
			
