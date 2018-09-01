#!/usr/bin/python

# send fragmented udp segments

from scapy.all import *
dip="129.129.224.21"
payload="A"*496+"B"*500
packet=IP(dst=dip,id=12345)/UDP(sport=7001,dport=7001)/payload

frags=fragment(packet,fragsize=500)

counter=1
for fragment in frags:
  print "Packet no#"+str(counter)
  print "==================================================="
  fragment.show() #displays each fragment
  counter+=1
  send(fragment)
