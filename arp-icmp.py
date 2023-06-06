from scapy.all import * 
trames = rdpcap("ftp-total.pcapng")

icmp_ope =  {0: "ECHO REPLY", 8: "ECHO REQUEST"}
arp_ope = {1: "who-as", 2: "is-at"}
for i in trames:
    if i.haslayer("ARP"):
        print("ARP :")
        print(f"Ope : {arp_ope[i[ARP].op]}")
        print(f" Src : {i[ARP].hwsrc}")
        print(f"DST : {i[ARP].hwdst}\n")
    elif i.haslayer("ICMP"):
        ope = icmp_ope[i[ICMP].type]
        print("ICMP")
        print(f"Ope : {ope}")
        print(f"IP Src : {i[IP].src}")
        print(f"IP Dst : {i[IP].dst}")
        print(f"Mac Src : {i[Ether].src}")
        print(f"Mac Dst : {i[Ether].dst}\n")
