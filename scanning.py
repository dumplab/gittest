import os,re,requests,socket,sys
def bl1():
        for x in range(1,80):
                print("")
bl1()
hostname = raw_input("\033[1;31;40mdomain:\033[0;37;40m ")
bl1()
print("BASIC \033[1;31;40mSCANNING\033[0;37;40m RESULTS")
print("\033[1;32;40m**********************\033[0;37;40m")
try:
        addr = socket.gethostbyname(hostname)
except:
        print("Nothing found for " + hostname + " make sure you're connected to the NET")
        sys.exit(1)

print("DOMAIN: " + str(hostname))
print("IP:     " + str(addr))
# DNS MX
with os.popen("dig " + hostname + " MX +noall +answer") as response:
        r = response.readlines()
for l in r:
        if re.match(hostname,l):
                tmpMX = re.split(" ",l)
                for x in tmpMX:
                        MX = tmpMX[len(tmpMX)-1]
                        MX = MX[:-2]
                        MXIP = socket.gethostbyname(MX)
                        break
try:
        print("MX:     " + MX + " (" + MXIP + ")")
except:
        print("MX:     no MX record")

# web app scan
r = requests.get("http://" + hostname)
try:
        print("HTTP:   " + str(r.headers['Server']))
except:
        print("HTTP:   error")

# SMTP
try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((MXIP,25))
        recv = s.recv(1024)
        myrecv = str(recv)
        s.send("quit")
        s.close()
        print("SMTP:   " + myrecv.strip())
except:
        print("SMTP:   not available")
# WHOIS
g = re.split("\.",hostname)
whoisHost = "whois.nic." + str(g[len(g)-1])
try:
        w = socket.gethostbyname(whoisHost)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((w,43))
        s.send(hostname+"\r\n")
        recv = s.recv(1024)
        s.close()
        print("WHOIS:  output=>")
        tmpWhois = re.split("\n",str(recv))
        for x in tmpWhois:
                print("        " + str(x))

except:
        print("WHOIS:  check if " + str(whoisHost)) + " exists"

round2 = raw_input("\033[1;31;40mcontinue? \033[0;37;40m ")
