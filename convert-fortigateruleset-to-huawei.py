#!/usr/bin/python
# Convert a Fortigate ruleset (from a configurationfile) into a Huawei USG config converting vdoms into vsys
#
# Convertion features:
# * VDOM names
# * address objects
# * address group objects
# * proto/services
# * only converts VDOM part!
# 
# only use at your own risk!
import re,getopt,sys

# user defs
fgconfigfile = "/path/to/your/forticonfigfile"
vdomFilter   = "[a-z]{4}$" # only match vdoms with this, change this to your needs
debug        = False

try:
	opts, args = getopt.getopt(sys.argv[1:],"hdv:",["vdom=","ofile="])
except getopt.GetoptError:
	print("Usage: convert-fortigateruleset-to-huawei [OPTION]... [VDOM]...")
	sys.exit(2)
# process arguments
for opt, arg in opts:
	if opt == '-h':
		print("Usage: convert-fortigateruleset-to-huawei [OPTION]... [VDOM]...")
		print("Convert Fortigate configuration into Huwai USG configuration.")
		print("(c) 2018 - dumplab")
		print("")
		print("Options")
		print(" -v,--vdom   only convert a specific vdom")
		print(" -d,--debug  enable debug output")
		print(" -h          print this help")
		sys.exit()
	elif opt in ("-v", "--vdom"):
		vdomFilter = arg
	elif opt in ("-d", "--debug"):
		debug = True

# flags
inVdom                   = False
inVdomCapture            = False
inAddressSection         = False
inAddressGroupSection    = False
inServiceSection         = False
inAddressObjSection      = False
inAddressGroupObjSection = False
inServiceObjSection      = False
inPolicySection          = False
inPolicyObjSection       = False
afterGlobal              = False
convertedConfig          = ""
vdoms                    = []

class cAddress:
	def __init__(self):
		self.name        = ""
		self.address     = ""
		self.description = None
		self.usageCount  = 0

class cAddressGroup:
	def __init__(self):
		self.name        = ""
		self.address     = ""
		self.description = None
		self.usageCount  = 0
class cService:
	def __init__(self):
		self.name        = ""
		self.tcpDst      = None
		self.udpDst      = None
		self.description = None
		self.usageCount  = 0

class cRule:
	def __init__(self):
		self.name        = ""
		self.address     = ""
		self.srcZone     = ""
		self.dstZone     = ""
		self.srcAddr     = []
		self.dstAddr     = []
		self.service     = []
		self.action      = "deny" # if no action appears, forti implies a deny
		self.description = None
		self.enabled     = True   # always enabled

class cVDOM:
	def __init__(self):
		"""Default Values"""
		self.name         = ""
		self.address      = []
		self.addressGroup = []
		self.service      = []
		self.rule         = []

print("# *************************************")
print("# * FortiGate to Huawei USG Converter *")
print("# *************************************")
print("# Use at your own risk ... always verify results")
fg = open(fgconfigfile,'r')

for line in fg.readlines():
	# useful part starts after config global
	if re.search("^config.global$", line):
		afterGlobal = True

	if afterGlobal:
		if re.search("^config.vdom$", line):
			if debug:
				print("Entering VDOM")
			inVdom = True

		if inVdom:
			# end of a vdom config
			if re.search("^config router static$", line):
				if inVdomCapture:
					vdoms.append(newVDOM) # add all to the list
				inVdom = False
				inVdomCapture = False
				newVDOM = None
			if re.search("^edit." + vdomFilter, line):
				# create a new vdom object
				newVDOM = cVDOM()
				na = line.strip('\n')
				na = na[10:]
				# set vdom name, please note vsys should not start with number on usg
				newVDOM.name = na
				inVdomCapture = True

			# we are inside a vdom config
			if inVdomCapture:
				# address objects
				if inAddressSection:
					if inAddressObjSection:
						if re.search("set subnet", line):
							na = line.strip('\n')
							na = na[(na.find("subnet")+7):]
							na = na.split()
							nx = na[0] + " mask " + na[1]
							newAddress.address = nx
						if re.search("set comment", line):
							na = line.strip('\n')
							na = na[(na.find("comment")+7):]
							na = na.replace('"','')
							newAddress.description = na
						if re.search("next$", line):
							# add to address
							newVDOM.address.append(newAddress)
							inAddressObjSection = False
					if re.search("edit", line):
						skip = False
						nl = line.strip('\n')
						nl = nl[(nl.find("edit")+5):]
						nl = nl.strip('"')
						if re.search("any|all|none",nl):
							skip = True
						if skip==False:
							# create new address
							newAddress = cAddress()
							newAddress.name = nl.lower()
							inAddressObjSection = True
					if re.search("^end", line):
						inAddressSection = False

				# address GROUP section
				if inAddressGroupSection:
					if inAddressGroupObjSection:
						if re.search("set member", line):
							na = line.strip('\n')
							na = na[(na.find("member")+7):]
							na = na.strip('"')
							newAddressGroup.address = na
						if re.search("next$", line):
							# add to address group list
							newVDOM.addressGroup.append(newAddressGroup)
							inAddressGroupObjSection = False
					if re.search("edit", line):
						nl = line.strip('\n')
						nl = nl[(nl.find("edit")+5):]
						nl = nl.strip('"')
						# create new group address
						newAddressGroup = cAddressGroup()
						newAddressGroup.name = nl.upper()
						inAddressGroupObjSection = True
					if re.search("^end", line):
						inAddressGroupSection = False

				# service section
				if inServiceSection:
					if inServiceObjSection:
						if re.search("set tcp-portrange", line):
							na = line.strip('\n')
							na = na[(na.find("tcp-portrange")+14):]
							na = na.strip('"')
							# lookin for things like 1025-65535:5064-5065 which defines a source port range
							na = na.split(':')
							if len(na)>1:
								dp = na[1]
							else:
								dp = na[0]
							newService.tcpDst = dp
						if re.search("set udp-portrange", line):
							na = line.strip('\n')
							na = na[(na.find("udp-portrange")+14):]
							na = na.strip('"')
							# lookin for things like 1025-65535:5064-5065 which defines a source port range
							na = na.split(':')
							if len(na)>1:
								dp = na[1]
							else:
								dp = na[0]
							newService.udpDst = dp
						if re.search("set comment", line):
							na = line.strip('\n')
							na = na[(na.find("comment")+7):]
							na = na.replace('"','')
							newService.description = na
						if re.search("next$", line):
							# add to address group list
							newVDOM.service.append(newService)
							inServiceObjSection = False
					if re.search("edit", line):
						nl = line.strip('\n')
						nl = nl[(nl.find("edit")+5):]
						nl = nl.strip('"')
						# skip service PING
#						if re.search("PING",nl):
#							inServiceSection = False
#						else:
#							newService = cService()
#							newService.name = nl.lower()
#							inServiceObjSection = True
						
						newService = cService()
						newService.name = nl.lower()
						inServiceObjSection = True
						# consideer every service
#						passedWebproxy = True
#						# create new group address
#						if passedWebproxy:
#							newService = cService()
#							newService.name = nl.lower()
#							inServiceObjSection = True
#						if re.search("webproxy",nl):
#							passedWebproxy = True
					if re.search("^end", line):
						inServiceSection = False

				# policy section
				if inPolicySection:
					if inPolicyObjSection:
						if re.search("set srcintf", line):
							na = line.strip('\n')
							na = na[(na.find("srcintf")+8):]
							na = na.replace('"','')
							newRule.srcZone = na
						if re.search("set dstintf", line):
							na = line.strip('\n')
							na = na[(na.find("dstintf")+8):]
							na = na.replace('"','')
							newRule.dstZone = na
						if re.search("set srcaddr", line):
							na = line.strip('\n')
							na = na[(na.find("srcaddr")+8):]
							na = na.replace('"','')
							# split into multiple services
							sa = []
							sa = re.split(' ', na)
							newRule.srcAddr = sa
						if re.search("set dstaddr", line):
							na = line.strip('\n')
							na = na[(na.find("dstaddr")+8):]
							na = na.replace('"','')
							# split into multiple services
							da = []
							da = re.split(' ', na)
							newRule.dstAddr = da
						if re.search("set comments", line):
							na = line.strip('\n')
							na = na[(na.find("comments")+9):]
							na = na.replace('"','')
							newRule.description = na
						if re.search("set action", line):
							na = line.strip('\n')
							na = na[(na.find("action")+7):]
							na = na.replace('"','')
							if re.search("accept",na):
								na = "permit"
							newRule.action = na
						if re.search("set service", line):
							na = line.strip('\n')
							na = na[(na.find("service")+8):]
							na = na.replace('"','')
							# split into multiple services
							sv = []
							sv = re.split(' ', na)
							newRule.service = sv
						if re.search("set status", line):
							na = line.strip('\n')
							na = na[(na.find("status")+7):]
							na = na.replace('"','')
							newRule.enabled = False
						if re.search("next$", line):
							# add policy to policy list
							newVDOM.rule.append(newRule)
							inPolicyObjSection = False
					if re.search("edit", line):
						nl = line.strip('\n')
						nl = nl[(nl.find("edit")+5):]
						nl = "fg-policy-id-" + nl.strip('"')
						# create new policy
						newRule = cRule()
						newRule.name = nl
						inPolicyObjSection = True
					if re.search("^end", line):
						inPolicySection = False

				# switch address section
				if re.search("^config.firewall.address$", line):
					inAddressSection = True

				# switch address group section
				if re.search("^config.firewall.addrgrp$", line):
					inAddressGroupSection = True

				# switch service section
				if re.search("^config.firewall.service.custom$", line):
					inServiceSection = True
					passedWebproxy   = False

				# switch policy section section
				if re.search("^config.firewall.policy$", line):
					inPolicySection = True

# close file
fg.close()

# for stats
stVdoms = 0
stAddr  = 0
stAddrG = 0
stSvc   = 0
stRle   = 0
stDis   = 0

# validate objects
for vdom in vdoms:
	if debug:
		print("Validate objects in VDOM " + vdom.name)

	# check rule for rule
	for rle in vdom.rule:
		if debug:
			print(" rule name:" + rle.name)
		# mark services
		for rlsvc in rle.service:
			for svc in vdom.service:
				if rlsvc==svc.name:
					svc.usageCount += 1
		# mark destination address
		for rlsa in rle.srcAddr:
			# check address object
			for da in vdom.address:
				if rlsa==da.name:
					da.usageCount += 1
			# check address group object
			for dag in vdom.addressGroup:
				if rlsa==dag.name:
					dag.usageCount += 1
			
		# mark destination address
		for rlda in rle.dstAddr:
			# check address object
			for da in vdom.address:
				if rlda==da.name:
					da.usageCount += 1
			# check address group object
			for dag in vdom.addressGroup:
				if rlda==dag.name:
					dag.usageCount += 1

	#there is alos address in address group
	for adg in vdom.addressGroup:
		xx = adg.address.split()
		for x in xx:
			sAdr = x.strip('"')
			for da in vdom.address:
				if sAdr==da.name:
					da.usageCount += 1

# create configuration string from objects
for vdom in vdoms:
	stVdoms += 1
	if debug:
		print("VDOM " + vdom.name)
	# create vsys
	convertedConfig += "# create vsys " + vdom.name + "\n"
	# switch to vsys and set the zones and zonenames
	convertedConfig += "#\nswitch vsys " + vdom.name + "\n"
	convertedConfig += "#\nsystem-view\n"
	# change this to whatever you need
	convertedConfig += "#\nfirewall zone name " + vdom.name.upper() + "_inside\n set priority 75\n add interface 10GE1/1/0\n"
	convertedConfig += "#\nfirewall zone name " + vdom.name.upper() + "_outside\n set priority 10\n add interface 10GE1/0/0\n"

	for ad in vdom.address:
		stAddr += 1
		if debug:
			print(" address name:" + ad.name + "\t\taddr:" + ad.address)
		if ad.usageCount==0:
			convertedConfig += "\n# **********************************************************************\n"
			convertedConfig += "# WARNING: NEXT ADDRESS IS NOT REFERENCED IN ANY RULE OR ADDRESS-GROUP *\n"
			convertedConfig += "# **********************************************************************"
		convertedConfig += "#\nip address-set " + ad.name + " type object\n"
		if ad.description is not None:
			convertedConfig += " description " + ad.description + "\n"
		convertedConfig += " address 0 " + ad.address + "\n"

	for adg in vdom.addressGroup:
		stAddrG += 1
		if debug:
			print(" address group name:" + adg.name + "\t\taddr:" + adg.address)
		convertedConfig += "#\nip address-set " + adg.name + " type group\n"
		xx = adg.address.split()
		for x in xx:
			convertedConfig += " address address-set " + x.strip('"') + "\n"

	for svc in vdom.service:
		stSvc += 1
		if debug:
			print(" service name:" + svc.name)
		if svc.usageCount==0:
			convertedConfig += "\n# *****************************************************\n"
			convertedConfig += "# WARNING: NEXT SERVICE IS NOT REFERENCED IN ANY RULE *\n"
			convertedConfig += "# *****************************************************"
		convertedConfig += "#\nip service-set " + svc.name + " type object\n"

		if svc.description is not None:
			convertedConfig += " description " + svc.description + "\n"
		if svc.tcpDst is not None:
			if debug:
				print("  tcp port(s):" + svc.tcpDst)
			tcpD = svc.tcpDst.split(' ')
			if len(tcpD)>1:
				for x in range(len(tcpD)):
					tcpD[x] = re.sub('\-',' to ',tcpD[x])
					convertedConfig += " service protocol tcp source-port 0 to 65535 destination-port " + tcpD[x] + "\n"
			else:
				tcpD[0] = re.sub('\-',' to ',tcpD[0])
				convertedConfig += " service protocol tcp source-port 0 to 65535 destination-port " + tcpD[0] + "\n"
		if svc.udpDst is not None:
			if debug:
				print("  udp port(s):" + svc.udpDst)
			udpD = svc.udpDst.split(' ')
			if len(udpD)>1:
				for x in range(len(udpD)):
					udpD[x] = re.sub('\-',' to ',udpD[x])
					convertedConfig += " service protocol udp source-port 0 to 65535 destination-port " + udpD[x] + "\n"
			else:
				udpD[0] = re.sub('\-',' to ',udpD[0])
				convertedConfig += " service protocol udp source-port 0 to 65535 destination-port " + udpD[0] + "\n"

	convertedConfig += "#\nsecurity-policy\n"
	for rle in vdom.rule:
		stRle += 1
		if debug:
			print(" rule name:" + rle.name)
		convertedConfig += " rule name " + rle.name + "\n"
		if rle.enabled==False:
			stDis += 1
			convertedConfig += "  disable\nY\n"
		if rle.description is not None:
			convertedConfig += "  description \"" + rle.description + "\"\n"
		convertedConfig += "  source-zone " + rle.srcZone + "\n  destination-zone " + rle.dstZone + "\n"
		for sa in rle.srcAddr:
			convertedConfig += "  source-address address-set " + sa + "\n"
		for da in rle.dstAddr:
			convertedConfig += "  destination-address address-set " + da + "\n"
		for sv in rle.service:
			if re.search("PING",sv):
				sv = "ping"
			if re.search("ALL",sv):
				sv = "any"
			convertedConfig += "  service " + sv.lower() + "\n"
		convertedConfig += "  action " + rle.action + "\n"
convertedConfig += "#\nquit\n"

print("# =====================")
print("# CONVERSION STATISTICS")
print("# =====================")
print("# " + str(stVdoms) + " vdom")
print("# " + str(stAddr) + " address objects")
print("# " + str(stAddrG) + " address group objects")
print("# " + str(stSvc) + " service objects")
print("# " + str(stRle) + " rules (" + str(stDis) + " rules disabled)")
print("#")
print("# ****** START CONFIGURATION ******")
print(convertedConfig)
