#!/usr/bin/python
"""Bridge traffic between interfaces. Reduce MSS size on the flow

just a start ...

Requires scapy

"""
__author__    = "dumplab"
__copyright__ = "2022 dumplab"
__license__   = "MIT"
__version__   = "1.0"

from scapy.all import *
import re
import time

# default capture settings
bridgeInterface    = ["ens2f1","ens5f0"] # interfaces to bridge
tcpMSS             = 60                  # decrease MSS by this bytes
# internals
timer              = int(time.time())

def pkt_callback_xfrm12(pkt):
        global tcpMSS
        retVal = True
        if pkt.haslayer(TCP):
                # ignore everything without a SYN or SYN&ACK only flag set
                if not (pkt[TCP].flags==2 or pkt[TCP].flags==18):
                        return retVal
                tcpOpts = pkt[TCP].options # list of options will be parsed
                # read TCP options used to create signature string
                for opt in tcpOpts:
                        if re.search("MSS",str(opt[0])):
                                print("MSS found")
                #ret = performAttack(pkt)
                retVal = pkt
        return retVal

def pkt_callback_xfrm21(pkt):
        global tcpMSS
        retVal = True
        if pkt.haslayer(TCP):
                # ignore everything without a SYN or SYN&ACK only flag set
                if not (pkt[TCP].flags==2 or pkt[TCP].flags==18):
                        return retVal
                #ret = performAttack(pkt)
                retVal = pkt
        return retVal

print("********************************************************")
print("* Bridge and forge traffic                             *")
print("********************************************************")
print("* Bridge interface: " + str(bridgeInterface[0]))
print("* Bridge interface: " + str(bridgeInterface[1]))
print("* Reduce TCP MSS:   " + str(tcpMSS) + " bytes")

print("********************************************************")
print("READY... processing packets")
print("********************************************************")
# call scapy sniff function
pkts = bridge_and_sniff(bridgeInterface[0],bridgeInterface[1],xfrm12=pkt_callback_xfrm12,xfrm21=pkt_callback_xfrm21,count=0,store=0)

