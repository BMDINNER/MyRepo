from scapy.all import *

def sniffPckt(pckt):
	pckt.show()


def startSniff():
	scapySniff = sniff(prn = sniffPckt,timeout=50,iface='eth0',stop_filter = lambda x:x.haslayer(ICMP))
	wrpcap('github.pcap',scapy_sniff)

def startRead():
	scapyRead = rdpcap('github.pcap')
	ip_list= []
	for pckt in scapyRead:
		if IP in pckt:
			if pckt[IP].src not in ip_list:
				ip_list.append(pckt[IP].src)
		else:
			pckt.show()
	print(ip_list)
print("""
	1:Sniff
	2:Read
	""")

optionPicked = input(">>	")

if(optionPicked == "1"):
	startSniff()
elif(optionPicked =="2"):
	startRead()
else:
	print("Unvalid Option")