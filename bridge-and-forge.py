#!/usr/bin/python
"""Bridge traffic between interfaces. Adjust MSS size on the flow

Requires scapy

"""
__author__    = "dumplab"
__copyright__ = "2022 dumplab"
__license__   = "MIT"
__version__   = "1.0"

from scapy.all import *
import re

# default capture settings
bridgeInterface    = ["enp1s0f0","enp1s0f1"] # interfaces to bridge
tcpMSS             = 1400                    # adjust to this size
debug              = False                   # enable debugging
cnt                = 0

def modifyMSS(pkt):
        global tcpMSS
        global cnt
        tcpOpts = pkt[TCP].options # list of options
        if len(tcpOpts)==0:
                return pkt
        if debug:
                print("TCP flags:" + str(pkt[TCP].flags))
                print("TCP opt:" + str(tcpOpts))
        newOpt = []
        for opt in tcpOpts:
                if re.search("MSS",str(opt[0])):
                        m,v = opt
                        if v > tcpMSS:
                                newOpt.append(('MSS',tcpMSS))
                        else:
                                newOpt.append(opt)
                else:
                        newOpt.append(opt)
        if debug:
                print("New TCP opt:" + str(newOpt))
        # save new opts
        pkt[TCP].options = newOpt
        del pkt[TCP].chksum # delete checksum so scapy can recompute
        if debug:
                cnt += 1
                print("Modified packet #" + str(cnt) + " from source: " + str(pkt[IP].src) + " to " + str(pkt[IP].dst))
        return pkt

def pkt_callback_xfrm12(pkt):
        retVal = True
        if pkt.haslayer(TCP):
                # ignore everything without a SYN or SYN&ACK or handshake options
                if not (pkt[TCP].flags==2 or pkt[TCP].flags==18 or pkt[TCP].flags==66 or pkt[TCP].flags==194):
                        return retVal
                retVal = modifyMSS(pkt)
        return retVal

def pkt_callback_xfrm21(pkt):
        retVal = True
        if pkt.haslayer(TCP):
                # ignore everything without a SYN or SYN&ACK or handshake options
                if not (pkt[TCP].flags==2 or pkt[TCP].flags==18 or pkt[TCP].flags==66 or pkt[TCP].flags==194):
                        return retVal
                retVal = modifyMSS(pkt)
                #ret = performAttack(pkt)
        return retVal

print("********************************************************")
print("* Bridge and forge traffic                             *")
print("********************************************************")
print("* Bridge interface: " + str(bridgeInterface[0]))
print("* Bridge interface: " + str(bridgeInterface[1]))
print("* Reduce TCP MSS:   " + str(tcpMSS) + " bytes")

print("********************************************************")
print("READY... bridging packets")
print("********************************************************")
pkts = bridge_and_sniff(bridgeInterface[0],bridgeInterface[1],xfrm12=pkt_callback_xfrm12,xfrm21=pkt_callback_xfrm21,count=0,store=0)
