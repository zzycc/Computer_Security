from scapy.all import *
import time
import sys

def debug(s):
    print('#{0}'.format(s))
    sys.stdout.flush()
def is_up(ip):
    icmp = IP(dst=ip)/ICMP()
    resp = sr1(icmp, timeout=0.5,verbose=0)
    if resp == None:
        return False
    else:
        return True


if __name__ == "__main__":
    conf.iface = sys.argv[1]
    ip_addr = sys.argv[2]
    start = time.time()
    if is_up(ip_addr):
        for port in range(1,1025):
            if (time.time()-start)>300:
                sys.exit("time out")
            p = IP(dst = ip_addr)/TCP(dport=port,flags='S')
            answered, unanswered = sr(p,verbose=0,timeout=0.05)
            for req, resp in answered:
                if not resp.haslayer(TCP):
                    continue
                tcp_layer = resp.getlayer(TCP)
                if tcp_layer.flags ==0x12:
                    send_rst = sr(IP(dst = ip_addr)/TCP(dport = port,flags="R"),timeout=0.05,verbose=0)
                    string = str(ip_addr) + "," + str(port)
                    print(string)


