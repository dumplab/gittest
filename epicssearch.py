#!/usr/bin/python
"""Basic EPICS CA_PROTO_SEARCH sniffer using scapy. Captures EPICS UDP traffic, identifies replies and prints first reply header having a tcp port <> 5064

Only the first header in the EPICS message is processed. So we may miss other ports, as a EPICS msg can contain many CA_PROTO-SEARCH replies (one reply for each SearchID/PV).
"""

## Import Scapy module
from scapy.all import *
import sys, re, time

#vars
captureInterface = "ens192"
captureFilter    = "(udp[8:2]==0x00) and (udp[24:2]==0x06) and (udp[26:2]==0x08) and (udp[30:2]==0x00) and port 5064" # can be extended with networks or whatever
debug            = False

# callback function to process EPICS msg
def procepics(pkt):
        if debug:
                pkt.show()
        myLoad = None
        try:
                myLoad = pkt[Raw].load
        except:
                pass

        # identify CA_PROTO_SEARCH reply in first EPICS header, this is done whily Payload==8 and DataCount==0
        if myLoad[16]=='\x00' and myLoad[17]=='\x06' and myLoad[18]=='\x00' and myLoad[19]=='\x08' and myLoad[22]=='\x00' and myLoad[23]=='\x00':
                # get port from first header
                hexPort = str(myLoad[20].encode("HEX")) + str(myLoad[21].encode("HEX"))
                intPort = int(hexPort,16)
                if intPort!=5064:
                        print(pkt[IP].src + ":" + str(intPort) + ":" + str(int(time.time())))

print("********************************************************")
print("* Capture interface: " +captureInterface)
print("* Capture filter:    " + captureFilter)
print("********************************************************")
print("OK ... capturing and printing CA_PROTO_SEARCH replies")

# call scapy sniff function
pkts = sniff(iface=captureInterface,filter=captureFilter, count=0 ,prn=procepics, store=0)
