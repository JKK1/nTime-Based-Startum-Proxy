import time, threading, select, json, socket

import stratum

from cryptography.fernet import Fernet

def encrypt(message, key):
    return Fernet(key).encrypt(message.encode())

def decrypt(token, key):
    return Fernet(key).decrypt(token).decode()

class Communications(threading.Thread):
	def __init__(self):
		self.isAlive = True
		self.keepAlive = True

		self.port = 5444

		self.lastNonce = 0

		self.connections = []

		self.key = b'1YVgrQW9hY-EXkfAuo8vA7TCZ6lPUVYEJc1qbGPpZ1M='


		self.communicationSocket=None
		self.initialize()

		threading.Thread.__init__(self)
		self.start()

	def decrypt(self, message):
		try:
			message = decrypt(message,self.key)
			message = json.loads(message)
			if int(message["id"])<=self.lastNonce:
				return False
			self.lastNonce=message["id"]
			

		except:
			return False



		return message




	def initialize(self):
		self.isAlive = True
		self.communicationSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.communicationSocket.bind(("0.0.0.0",self.port))
		self.communicationSocket.listen(1)

	def close(self):
		for conn in self.connections:
			self.removeConnection(conn)

		self.connections=[]

		"""try:
			self.communicationSocket.close()
		except:
			pass"""

	def update(self):
		if select.select([self.communicationSocket],[],[],0)[0]:
			c,_ = self.communicationSocket.accept()
			self.connections.append([c,time.time()])

		for conn,timed in self.connections.copy():
			if timed+60*5<time.time():
				self.removeConnection(conn)
			try:
				if select.select([conn],[],[],0)[0]:
					self.handle(conn.recv(4*1024), conn)
			except:
				self.removeConnection(conn)


	def handle(self, message, conn):
		if not message:
			self.removeConnection(conn)
			return
		decrypted = self.decrypt(message)
		if not decrypted:
			self.removeConnection(conn)
			return
		self.handleDecrypted(decrypted,conn)

	def handleDecrypted(self, data, conn):
		x=0
		for connection in self.connections:
			if connection[0]==conn:
				break
			x+=1
		self.connections[x][1]=time.time()
		if data["method"]=="mining.getShares":
			conn.sendall(json.dumps(stratum.stratum.getShares()).encode()+b"\n")
		elif data["method"]=="ping":
			conn.sendall(json.dumps({"ping":"pong"}).encode()+b"\n")

		elif data["method"]=="killOrder":
			stratum.stratum.killOrder()
			conn.sendall(json.dumps({"ping":"pong"}).encode()+b"\n")

	def removeConnection(self, conn):
		try:
			conn.close()
		except:
			pass

		try:
			for connection in self.connections.copy():
				if connection[0]==conn:
					self.connections.remove(connection)
				
		except:
			pass


			
			

	def shutdown(self):
		self.isAlive = False
		self.keepAlive = False

	def run(self):
		while self.keepAlive:
			while self.isAlive:
				try:
					self.update()
					time.sleep(0.03)
				except:
					raise
					self.isAlive = False
			self.close()
			#self.initialize()

		


communications = None

def start():
	global communications
	communications = Communications()