from scapy.all import *  
import chardet

def telnet_monitor(pkt):  
    # pkt.show()
    
    print("psrc: ",pkt['ARP'].psrc)

PTKS = sniff(prn = telnet_monitor,filter = "arp",store=1,timeout=15) 
# PTKS = sniff(prn = telnet_monitor,filter = "tcp",store=1,timeout=15) 

# print(PTKS.res) # 由packet组成的list
# print(PTKS.summary()) # 等价于PTKS.show()
