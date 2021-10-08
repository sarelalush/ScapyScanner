from scapy.all import *
from collections import namedtuple

Answer = namedtuple('ans','ip mac')

def arp_scan(ip):
    req = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip)
    ans , _ = srp(req,timeout=0.5,retry=1)
    results = []

    for _ , packet in ans:
        results.append(Answer(packet.psrc,packet.hwsrc))
    return results


def main():
    all_answers = []
    for curr_ip in range(255):
        all_answers.append(arp_scan(f'10.0.0.{curr_ip}'))
        
    for answer in all_answers:
        if answer != []:
            for packet in answer:
                print(f'IP: {packet.ip} Mac Addres: {packet.mac}')

if __name__ == "__main__":
    main()


