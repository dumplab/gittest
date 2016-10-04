"""Connect miniHomeNet relay - Requires python requests lib (HTTP for Humans)

Using this class one can connect to the relay (minihomenet.php) and autoregister this device. Configuration in config.json.
"""

__author__    = "dumplab"
__copyright__ = "2016 dumplab"
__license__   = "MIT"
__version__   = "0.1"
__status__    = "Development"

import json,platform,re,requests,subprocess,sys,time
requests.packages.urllib3.disable_warnings()

class minihomenet:
        """Main class"""

        def __init__(self):
		"""Set default attribute values only
		
		No arguments
		"""
		# definitions
		self.__configFile             = "config.json"
		self.__debugging              = False
		# do not change
		self.__config                 = {}
		self.__keepAliveTime          = 2 # keepAlive in seconds will be overwritten by relay
		self.__requests               = requests.session() # persistant
		self.__lastResponeCode        = ""
		self.__execCode               = ""
		self.__execArguments          = ""
		# *************************
		# *  CODES do not change  *
		# *************************
		# Request codes
		self.NET_GUEST_LOGIN        = "0099"
		self.NET_LOGIN              = "0100"
		self.NET_PING               = "0101"
		self.NET_LOGOUT             = "0102"
		self.NET_DEVICE_RENAME      = "0103"
		self.NET_SEND_MESSAGE       = "0104"
		self.NET_RETRIEVE_MESSAGE   = "0105"
		self.NET_DEVICE_LIST        = "0106"
		self.NET_SEND_INVITE        = "0109"
		self.NET_SEND_JOIN          = "0110"
		# Response codes
		self.NET_REQUEST_OK         = "0200"
		self.NET_EXEC_MESSAGE       = "0201"
		self.NET_REQUEST_UNKNOWN    = "0400"
		self.NET_SECRET_REQUIRED    = "0401"
		self.NET_SECRET_WRONG       = "0402"
		self.NET_DEVICE_UNKNOWN     = "0403"
		self.NET_DEVICE_LOGIN_FIRST = "0404"
		self.NET_SERVER_MAX_DEVICE  = "0405"
		self.NET_IP_ADDR_BLOCKED    = "0406"
		self.NET_GUEST_LOGIN_OFF    = "0407"
		self.NET_DATABASE_ERROR     = "0408"
		self.NET_NAME_FORMAT_ERROR  = "0600"
		self.NET_UID_FORMAT_ERROR   = "0601"
		self.NET_MSG_FORMAT_ERROR   = "0602"
		self.NET_INVALID_HIGHSCORE  = "0603"
		self.NET_MSG_AWAITING       = "0700"
		# Exec codes
		self.EXEC_PRINT_MESSAGE     = "0800"
		self.EXEC_SHUTDOWN_SYSTEM   = "0801"
		self.EXEC_STOP_SCRIPT       = "0802"
		self.EXEC_REMOTE_COMMAND    = "0803"
		# print start
		print("           _       _ _    _                      _   _      _   ")
		print("          (_)     (_) |  | |                    | \ | |    | |  ")
		print(" _ __ ___  _ _ __  _| |__| | ___  _ __ ___   ___|  \| | ___| |_ ")
		print("| '_ ` _ \| | '_ \| |  __  |/ _ \| '_ ` _ \ / _ \ . ` |/ _ \ __|")
		print("| | | | | | | | | | | |  | | (_) | | | | | |  __/ |\  |  __/ |_ ")
		print("|_| |_| |_|_|_| |_|_|_|  |_|\___/|_| |_| |_|\___|_| \_|\___|\__|")
		print("v." + __version__ + " (" + platform.system() + ")")
		print("")
		# Load configuration, make sure file ist read/write
		self.__loadConfig()

	def login(self):
		"""Login procedure ...
		
		No arguments
		"""
		# reset timer
		self.__keepAliveTimer = int(time.time()) + self.__keepAliveTime
		# prepare request
		self.__sanitizeRequest(self.NET_GUEST_LOGIN)
		# check response
		if self.__lastResponeCode==self.NET_REQUEST_OK:
			print("Registered to " + self.__config['MINIHOMENET_URL'] + " sending pings every " + str(self.__keepAliveTime) + "s")
			return True
		else:
			print("Problem connecting to " + self.__config['MINIHOMENET_URL'] + ". Enable debugging.")
			return False

	def getDevices(self):
		"""getDevices - retrieve list of all devices registered to relay
		
		No arguments
		"""
		self.__sanitizeRequest(self.NET_DEVICE_LIST)


	def __ping(self):
		"""__ping - sending pings to the relay
		
		No arguments
		"""
		self.__sanitizeRequest(self.NET_PING)

	def __retrieveMsg(self):
		"""__retrieveMsg - retrieve one message from relay at a time
		
		No arguments
		"""
		self.__sanitizeRequest(self.NET_RETRIEVE_MESSAGE)

	def run(self):
		"""run - call this method in a loop
		
		No arguments
		"""
		# send KEEPALIVE
		if int(time.time()) > self.__keepAliveTimer:
			self.__keepAliveTimer = int(time.time()) + self.__keepAliveTime
			self.__ping()

		# in case a msg is waiting on the relay
		if self.__lastResponeCode==self.NET_MSG_AWAITING:
			self.__retrieveMsg()

		# we got a message from the relay, now check the exec code
		if self.__lastResponeCode==self.NET_EXEC_MESSAGE:
			self.__lastResponeCode = ""
			# these messages will be printed out
			if self.__execCode==self.EXEC_PRINT_MESSAGE:
				print("GOT A MESSAGE: " + self.__execArguments)
			# shutdown the system, implement that on yourself as it requires special priviledges
			if self.__execCode==self.EXEC_SHUTDOWN_SYSTEM:
				print("EXECUTING SHUTDOWN ...")
			# stop minihomenet on the local system
			if self.__execCode==self.EXEC_STOP_SCRIPT:
				# prepare answer
				self.__sanitizeRequest(self.NET_SEND_MESSAGE,self.EXEC_PRINT_MESSAGE,"STOPPING SCRIPT NOW ... BYE")
				print("STOPPING SCRIPT ... BYE BYE")
				sys.exit(0)
			# execute command
			if self.__execCode==self.EXEC_REMOTE_COMMAND:
				print("EXECUTING COMMAND: " + self.__execArguments)
				res = (subprocess.Popen(self.__execArguments, shell=True, stdout=subprocess.PIPE).stdout.read())
				# prepare answer
				self.__sanitizeRequest(self.NET_SEND_MESSAGE,self.EXEC_PRINT_MESSAGE,self.__execArguments + " = " + str(res))
			# refresh in case there is more
			self.__ping()

	def __sanitizeRequest(self,requestCode,cmd="",content=""):
		if self.__debugging==True:
			print("SEND: " + self.__codeToString(requestCode))
		self.__lastResponeCode = ""
		header  = {'Content-Type': 'application/x-www-form-urlencoded'}
		if self.NET_GUEST_LOGIN==requestCode:
			payload = {'a': requestCode, 's': self.__config['MINIHOMENET_SECRET'], 'i': self.__config['MINIHOMENET_UID'], 'p': self.__config['MINIHOMENET_PW'], 'n': self.__config['MINIHOMENET_DEVICE_NAME']}
		else:
			payload = {'a': requestCode, 's': self.__config['MINIHOMENET_SECRET'], 'i': self.__config['MINIHOMENET_UID']}
		if self.NET_SEND_MESSAGE==requestCode:
			payload = {'a': requestCode, 's': self.__config['MINIHOMENET_SECRET'], 'i': self.__config['MINIHOMENET_UID'], 'm': content, 'd': 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF','c': cmd}
		try:
			response = self.__requests.post(self.__config['MINIHOMENET_URL'],data=payload, headers=header, verify=False)
			# check response
			self.__sanitizeResponse(response.status_code,response.content)
		except:
			if self.__debugging==True:
				print("SEND failed")
			return
			
	def __sanitizeResponse(self,httpCode,content):
		# always reset last response
		self.__lastResponeCode = self.NET_REQUEST_UNKNOWN
#		if self.__debugging==True:
#			print("HTTPcode:   " + str(httpCode))
#			print("RAWCONTENT: " + content)

		if 200==httpCode:
			# split up into miniHomeNet format
			tmp = []
			tmp = re.split(';;',content)
			# at least looks like something we could use
			if len(tmp)>0:
				self.__lastResponeCode = tmp[0]
				# verify
				
				if self.__debugging==True:
					print("RCVD: " + self.__codeToString(self.__lastResponeCode))
				# process error codes
				if self.__lastResponeCode==self.NET_DEVICE_UNKNOWN:
					print("Our device with UID " + self.__config['MINIHOMENET_UID'] + " is unknown to the relay")
					print("Either this device was deleted on relay or it was never registered. We stop here ... bye")
					sys.exit(0)
				# save execute codes and arguments
				if self.__lastResponeCode==self.NET_EXEC_MESSAGE:
					self.__execCode                  = tmp[3]
					self.__execArguments             = tmp[4]
				# login sends back the uid, save to config file
				if len(tmp)>5:
					self.__config['MINIHOMENET_UID'] = tmp[1]
					self.__config['MINIHOMENET_PW']  = tmp[2]
					self.__keepAliveTime             = int(tmp[3])
					self.__saveConfig()
				return True
			else:
				# possible format error
				print("Unknown format received ...")
				#sys.exit(0)
				
				return False
		else:
			return False

	def __loadConfig(self):
		if self.__debugging==True:
			print("Loading configuration from: " + self.__configFile)
		with open(self.__configFile, 'r') as f:
			self.__config = json.load(f)

	def __saveConfig(self):
		if self.__debugging==True:
			print("Saving configuration: " + self.__configFile)
		with open(self.__configFile, 'w') as f:
			json.dump(self.__config, f)

	def __codeToString(self,code):
		switcher = {
			"0099": "NET_GUEST_LOGIN",
			"0100": "NET_LOGIN",
			"0101": "NET_PING",
			"0102": "NET_LOGOUT",
			"0103": "NET_DEVICE_RENAME",
			"0104": "NET_SEND_MESSAGE",
			"0105": "NET_RETRIEVE_MESSAGE",
			"0106": "NET_DEVICE_LIST",
			"0107": "NET_SEND_HIGHSCORE",
			"0108": "NET_RETRIEVE_HIGHSCORE",
			"0109": "NET_SEND_INVITE",
			"0110": "NET_SEND_JOIN",
			"0200": "NET_REQUEST_OK",
			"0201": "NET_EXEC_MESSAGE",
			"0400": "NET_REQUEST_UNKNOWN",
			"0401": "NET_SECRET_REQUIRED",
			"0402": "NET_SECRET_WRONG",
			"0403": "NET_DEVICE_UNKNOWN",
			"0404": "NET_DEVICE_LOGIN_FIRST",
			"0405": "NET_SERVER_MAX_DEVICE",
			"0406": "NET_IP_ADDR_BLOCKED",
			"0407": "NET_GUEST_LOGIN_OFF",
			"0408": "NET_DATABASE_ERROR",
			"0600": "NET_NAME_FORMAT_ERROR",
			"0601": "NET_UID_FORMAT_ERROR",
			"0602": "NET_MSG_FORMAT_ERROR",
			"0603": "NET_INVALID_HIGHSCORE",
			"0700": "NET_MSG_AWAITING",
			"0800": "EXEC_PRINT_MESSAGE",
			"0801": "EXEC_SHUTDOWN_SYSTEM",
			"0802": "EXEC_STOP_SCRIPT",
			"0803": "EXEC_REMOTE_COMMAND",
		}
		return switcher.get(code, "unknown")

