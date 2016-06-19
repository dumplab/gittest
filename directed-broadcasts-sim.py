#!/usr/bin/python
""" Send Directed Broadcasts, for example simulate EPICS traffic

This script sends some udp datagrams as directed broadcasts - use on your own risk
"""

__author__    = "dumplab"
__copyright__ = "2014 dumplab"
__license__   = "MIT"
__version__   = "1.0"
__status__    = "Development"

import multiprocessing
import socket

# define broadcast addresses
bcAddress = ["172.16.0.255","172.16.8.255","172.16.40.255"]	# addresses, note router MUST be enabled to forward as l2 broadcasts "ip directed-broadcast"
bcPort    = 5064						# udp destination port to use
bcCount   = 4096						# datagrams we shall send

def udpFlood(myAddress):
	"""Send UDP datagram at fastest rate"""
	b = multiprocessing.current_process()
	print("Sending " + str(bcCount) + " UDP message(s) to " + str(SVI) + ":" + str(bcPort) + " PID(" + str(b.pid) + ")")
	# create socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
	for x in range(bcCount):
		sock.sendto("its-not-the-network",(myAddress,bcPort))

for SVI in bcAddress:
	p = multiprocessing.Process(target=udpFlood, args=(SVI,)).start()

