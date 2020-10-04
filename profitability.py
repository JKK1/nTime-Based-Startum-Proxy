import requests

def scrypt_nicehash():
	try:
		res = requests.get("https://api2.nicehash.com/main/api/v2/public/simplemultialgo/info/").json()
		for algo in res["miningAlgorithms"]:
			if algo["algorithm"]=="SCRYPT":
				return algo["paying"]*10000
		return 0
	except:
		return 0

def scrypt_prohashing():
	try:
		res = requests.get("https://prohashing.com/api/v1/status").json()
		return float(res["data"]["scrypt"]["estimate_current"])*1000000
	except:
		return 0

def scrypt_litecoinpool():
	try:
		res = requests.get("https://www.litecoinpool.org/api?api_key=7f4407c2e30b992afee496addd95a4f0").json()
		d=res["network"]["difficulty"]
		h=1000**4
		b=12.5
		s=86400
		r=res["pool"]["pps_ratio"]
		p=res["market"]["ltc_btc"]
		return b*h*s/d/2**32*r*p
	except:
		return 0

def scrypt_digibyte():
	try:
		d= float(requests.get("https://dgb.ccore.online/api/getdifficulty").text)
		h=1000**4
		res = requests.get("https://api.minerstat.com/v2/coins").json()
		for coin in res:
			if coin["coin"]=="BTC":
				btcprice=coin["price"]

		for coin in res:
			if coin["coin"]=="DGB" and coin["algorithm"]=="Scrypt":
				b = float(coin["reward_block"])
				p = coin["price"]/btcprice
				r=0.95
				s=86400
		return b*h*s/d/2**32*r*p #+x
	except:
		return 0


		



def sha256_nicehash():
	try:
		res = requests.get("https://api2.nicehash.com/main/api/v2/public/simplemultialgo/info/").json()
		for algo in res["miningAlgorithms"]:
			if algo["algorithm"]=="SHA256":
				return algo["paying"]*10**7
		return 0
	except:
		return 0

def sha256_prohashing():
	try:
		res = requests.get("https://prohashing.com/api/v1/status").json()
		return float(res["data"]["sha-256"]["estimate_current"])*10**9
	except:
		return 0

def sha256_bitcoin_f2Pool():
	try:
		res = requests.get("https://api.minerstat.com/v2/coins").json()
		for coin in res:
			if coin["coin"]=="BTC":
				return float(coin["reward"])*1000**5*24
	except:
		return 0

def sha256_bitcoinCash_f2Pool():
	try:
		res = requests.get("https://api.minerstat.com/v2/coins").json()
		for coin in res:
			if coin["coin"]=="BTC":
				btcprice=coin["price"]
		for coin in res:
			if coin["coin"]=="BCH":
				return float(coin["reward"])*1000**5*24*coin["price"]/btcprice
	except:
		return 0


def x11_nicehash():
	try:
		res = requests.get("https://api2.nicehash.com/main/api/v2/public/simplemultialgo/info/").json()
		for algo in res["miningAlgorithms"]:
			if algo["algorithm"]=="X11":
				return algo["paying"]*10**7
		return 0
	except:
		return 0

def x11_prohashing():
	try:
		res = requests.get("https://prohashing.com/api/v1/status").json()
		return float(res["data"]["sha-256"]["estimate_current"])*10**9
	except:
		return 0


def ethash_nicehash():
	try:
		res = requests.get("https://api2.nicehash.com/main/api/v2/public/simplemultialgo/info/").json()
		for algo in res["miningAlgorithms"]:
			if algo["algorithm"]=="DAGGERHASHIMOTO":
				return algo["paying"]*10**4
		return 0
	except:
		return 0

def ethash_ethereum():
	try:
		res = requests.get("https://api.minerstat.com/v2/coins").json()
		for coin in res:
			if coin["coin"]=="BTC":
				btcprice=coin["price"]
		for coin in res:
			if coin["coin"]=="ETH":
				return float(coin["reward"])*1000**4*24*coin["price"]/btcprice
	except:
		return 0
