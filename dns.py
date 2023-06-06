from scapy.all import *
trames = rdpcap('ftp-total.pcapng')

for paquet in trames: 
    if paquet.haslayer("UDP") and paquet[UDP].dport == 53:
        paquet.haslayer("DNS"):
        print("ENTÊTE DNS : ")
        print(f"Qr : {paquet[DNS].qr}")
        print(f"Opcode : {paquet[DNS].opcode}")
        print(f" Nom : {paquet[DNS].qd.qname}")
        print(f"Type : {paquet[DNS].qd.qtype}")

