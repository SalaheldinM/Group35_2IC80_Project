import argparse

argumentParser = argparse.ArgumentParser() # Initialize parser

# Positional arguments
argumentParser.add_argument('victim')

# Optional arguments
argumentParser.add_argument('-a', '--arp', action = 'store_true') # ARP Poisoning Attack Flag
argumentParser.add_argument('-d', '--dns', action = 'store_true') # DNS Spoofing Attack Flag
argumentParser.add_argument('-s', '--ssl', action = 'store_true') # SSL Stripping Attack Flag

# Parse arguments
parseArgs = argumentParser.parse_args()
victim = parseArgs.victim 
isARPPoisoningAttack = parseArgs.arp
isDNSStrippingAttack = parseArgs.dns
isSSLStrippingAttack = parseArgs.ssl

if (sum([isARPPoisoningAttack, isDNSStrippingAttack, isSSLStrippingAttack]) > 1):
    print('Multiple attacks cannot be executed at once')
    raise SystemExit(1)

# Start right attack
if isARPPoisoningAttack:
    print('ARP Poisoning Attack has been started')

if isDNSStrippingAttack:
    print('DNS Spoofing Attack has been started')

if isSSLStrippingAttack:
    print('SSL Stripping Attack has been started')
