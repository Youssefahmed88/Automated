from scapy.all import *

try:
    info = {}

    def analyzer(packet):
        if packet.haslayer(ICMP):
            info['Protocol'] = "ICMP"
        elif packet.haslayer(TCP):
            info['Protocol'] = "TCP"
        elif packet.haslayer(UDP):
            info['Protocol'] = "UDP"

        if packet.haslayer(IP):
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            info['src_mac'] = packet.src
            info['dst_mac'] = packet.dst

            if packet.haslayer(ICMP):
                info['src_port'] = "N/A"
                info['dst_port'] = "N/A"
            else:
                info['src_port'] = packet.sport
                info['dst_port'] = packet.dport

            info['size'] = len(packet)

            if packet.haslayer(Raw):
                info['Payload'] = packet[Raw].load
            else:
                info['Payload'] = "N/A"

            # Print information for each packet within the analyzer function
            print('----------------------------------------------------------')
            for key, value in info.items():
                print(f'{key} : {value}')
            print('----------------------------------------------------------')

    print("\n******** The Sniffer Dog Tool ********\n")
    interface=input('NIC: ')
    print('Start sniffing...')
    sniff(iface=interface, prn=analyzer, store=0)

except Exception as e:
    print(f'\nAn error occurred: {e}\n')
