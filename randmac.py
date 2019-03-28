#!/usr/bin/python

from scapy.all import *

maxFrames = 10
interface = "eth0"
cnt        = 0

while True:
        if cnt >= maxFrames:
                print("Send " + str(cnt) + " frames")
                break
        cnt += 1
        sendp(Ether(src=RandMAC(),dst="FF:FF:FF:FF:FF:FF")/ARP(op=2, psrc="0.0.0.0", hwdst="FF:FF:FF:FF:FF:FF")/Padding(load="X"*18),iface=interface)

        
        
        # or an ip/udp packet
#        randSrcIP = "172.19.19." + str(cnt+3)
#        print("Random IP: " + randSrcIP)
#        sendp(Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff")/IP(src=randSrcIP,dst="172.20.20.20")/UDP(dport=9)/b"hey",iface=interface)
