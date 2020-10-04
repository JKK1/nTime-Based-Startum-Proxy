import binascii
import socket
import time
import bcrypt
import hashlib
import json
import base64
import os


def in_range(a,index):
	if len(a)==0:
		return False
	if index>=len(a):
		return False
	if index<0 and index<-1*len(a):
		return False
	return True

def recvall(sock,object):
	try:
		BUFF_SIZE = 4096 # 4 KiB
		data = b''
		while True:
			part = sock.recv(BUFF_SIZE)
			data += part
			if len(part) < BUFF_SIZE:
				# either 0 or end of data
				break
		return data
	except socket.error:
		try:
			object.self_destruct()
		except:
			pass
	except Exception as e:
		raise e
	finally:
		pass




class Delayer(object):
	def __init__(self,milliseconds=10):
		self.milliseconds=milliseconds
		self.last_time=time.time()
	def wait(self):
		while self.last_time+self.milliseconds>time.time():
			time.sleep(0.03)



def handle_packet_error(func):
	def wrapper(*args, **kwargs):
		try:
			return func(*args, **kwargs)
		except Exception as e:
			raise e
		finally:
			pass
	return wrapper




def swap_endian_word(hex_word):
	'''Swaps the endianness of a hexidecimal string of a word and converts to a binary string.'''
	message = binascii.unhexlify(hex_word)
	if len(message) != 4: raise ValueError('Must be 4-byte word')
	return message[::-1]

def swap_endian_words(hex_words):
	'''Swaps the endianness of a hexidecimal string of words and converts to binary string.'''
	message = binascii.unhexlify(hex_words)
	if len(message) % 4 != 0: raise ValueError('Must be 4-byte word aligned')
	return b''.join([ message[4 * i: 4 * i + 4][::-1] for i in range(0, len(message) // 4) ])



def ping():
	s=socket.socket()
	t=time.time()
	s.connect(("localhost", 9999))
	n=float(s.recv(1024))
	return time.time()-t

def hash_password(password,salt=None):
	firsthash=pre_hash(password)
	if not salt:
		salt=bcrypt.gensalt()
	hashed = bcrypt.hashpw(firsthash, salt)
	return hashed


class FA2():
	def newSecret():
		secret = str(base64.b32encode(os.urandom(64)))[2:]
		secret = secret[:-2]
		return secret

	def getQRLink(name, secret):
		return "https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/{0}%20-%20{1}%3Fsecret%3D{2}".format(name, "", secret)

	def auth(nstr, secret):
		if not secret:
			return False
		# raise if nstr contains anything but numbers
		try:
			int(nstr)
		except:
			return False
		if len(nstr)!=6:
			return False

		tm = int(time.time() / 30)
		secret = base64.b32decode(secret+"=")
		# try 30 seconds behind and ahead as well
		for ix in [-1, 0, 1]:
			# convert timestamp to raw bytes
			b = struct.pack(">q", tm + ix)
			# generate HMAC-SHA1 from timestamp based on secret key
			hm = hmac.HMAC(secret, b, hashlib.sha1).digest()
			# extract 4 bytes from digest based on LSB
			offset = hm[-1] & 0x0F
			truncatedHash = hm[offset:offset+4]
			# get the code from it
			code = struct.unpack(">L", truncatedHash)[0]
			code &= 0x7FFFFFFF;
			code %= 1000000;
			if ("%06d" % code) == nstr:
				return True
				
		return False

def validate(item,typer="email"):
	if typer=="email":
		try:
			item=item.replace(" ","")
		except:
			return False
	if typer=="password":
		if type(item)!=type(""):
			return False
	if typer=="2FAcode":
		try:
			item=item.replace(" ","")
		except:
			return "0"
	if typer=="name":
		try:
			item=item.replace(" ","")
		except:
			return False
	return item

def log(message, error=False):
	ctime=time.ctime()
	if error:
		message="#### "+message
	return ctime+" "+message