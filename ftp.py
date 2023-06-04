from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        if 'USER' in payload:
            username = payload.split('USER ')[1].split('\r\n')[0]
            print(f"Username: {username}")
        elif 'PASS' in payload:
            password = payload.split('PASS ')[1].split('\r\n')[0]
            print(f"Password: {password}")
    for i in rdpcap('ftp-total.pcapng'):
            packet_callback(i)
#sniff(filter='tcp port 21', prn=packet_callback, store=0)