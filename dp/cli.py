# Import necessary packages
import argparse
# Import attacks
import attacks.all as attacks

def start():
    """Starts the CLI."""
    # Initialize parser
    argumentParser = argparse.ArgumentParser(
                                    prog = 'dp',
                                    description = 'Tool for (local) automated, persistent ARP poisoning, DNS Spoofing and SSL Stripping attacks',
                                    epilog = 'For more information please contact us')

    # Positional arguments
    argumentParser.add_argument('victimIP', type = str, help = 'IP Address of the (first) victim') # TODO: Type check for IP
    argumentParser.add_argument('interface', type = str, help = 'Interface to control for an attack')  # TODO: Type check for interface

    # Optional attack arguments
    argumentParser.add_argument('-a', '--arp', action = 'store_true', default = False, help = 'Use to request an ARP Poisoning Attack') # ARP Poisoning Attack Flag
    argumentParser.add_argument('-da', '--dnsarp', action = 'store_true', default = False,  help = 'Use to request a DNS (ARP) Spoofing Attack') # DNS (ARP) Spoofing Attack Flag
    argumentParser.add_argument('-sa', '--sslarp', action = 'store_true', default = False, help = 'Use to request an SSL (ARP) Stripping Attack') # SSL (ARP) Stripping Attack Flag

    # Optional specification arguments
    argumentParser.add_argument('-vtip', '--victimtwoip', type = str, dest = 'victimTwoIP', help = 'IP Address of the second victim') # TODO: Type check for IP
    argumentParser.add_argument('-gip', '--gatewayip', type = str, dest = 'gatewayIP', help = 'IP Address of the gateway') # TODO: Type check for IP
    argumentParser.add_argument('-dnsl', '--dnslist', nargs = '+', type = str, dest = 'dnsList', help = 'List of DNS names to spoof') # TODO: Type check for DNS names
    argumentParser.add_argument('-dnsil', '--dnsiplist', nargs = '+', type = str, dest = 'dnsIPList', help = 'List of IP addresses to spoof DNS names to') # TODO: Type check for DNS names

    # Parse positional arguments
    parseArgs = argumentParser.parse_args() # Parse arguments
    victimIP = parseArgs.victimIP
    interface = parseArgs.interface

    # Parse optional attack arguments
    isARPPoisoningAttack = parseArgs.arp
    isDNSARPStrippingAttack = parseArgs.dnsarp
    isSSLARPStrippingAttack = parseArgs.sslarp

    def printHome():
        """Prints a home screen for users that have not explicitly chosen an attack"""
        print('Welcome to the Default Project attack tool by Group 35.\n')   

    def printExit():
        """Prints a exit message for users that quit the attack selection screen"""
        print('\nExiting Default Project Attack tool')    

    def attackPrompt():
        """Returns an attack chosen by the user."""
        attackNumber = input('Please pick an attack (number):\n[1] ARP Poisoning Attack\n[2] DNS (ARP) Spoofing Attack\n[3] SSL (ARP) Stripping Attack)\nPress [CTRL+C] to quit.\nYour pick: ')
        if attackNumber == 1: # ARP Poisoning Attack
            # Initialize missing variables
            victimTwoIP = raw_input('Please provide the IP address of the second victim: ')

            return attacks.ARPPoisoning(victimIP, victimTwoIP, interface) # TODO: Adapt script
        elif attackNumber == 2: # DNS (ARP) Spoofing Attack Flag
            # Initialize missing variables
            gatewayIP = raw_input('Please provide the IP address of the gateway: ')
            dnsList = raw_input('Please provide the DNS names: ').split()
            dnsIPList = raw_input('Please provide the IP Addresses to spoof DNS names to: ').split()

            return attacks.ARPDNSSpoofing(victimIP, gatewayIP, dnsList, dnsIPList, interface) # TODO: Adapt script
        elif attackNumber == 3: # SSL (ARP) Stripping Attack Flag
            # Initialize missing variables
            gatewayIP = raw_input('Please provide the IP address of the gateway: ')

            return attacks.ARPSSLStripping(victimIP, gatewayIP, interface) # TODO: Adapt script
        else:
            print('Invalid choice, please try again!')
            return attackPrompt() # Reset the prompt

    # Check optional attack arguments
    numberAttacks = sum([isARPPoisoningAttack, isDNSARPStrippingAttack, isSSLARPStrippingAttack])

    # Exit on invalid configurations
    if numberAttacks > 1:
        print('Multiple attacks cannot be executed at once')
        raise SystemExit(1)
        
    # Start right attack
    if isARPPoisoningAttack:
        # Initialize related flags
        victimTwoIP = parseArgs.victimTwoIP

        # Check related flags
        if victimTwoIP == None:
            print('Second victim IP address was not found, please specify using -vtip')
            raise SystemExit(1)

        # Assign attack
        attack = attacks.ARPPoisoning(victimIP, victimTwoIP, interface) # TODO: Adapt script
    elif isDNSARPStrippingAttack:
        # Initialize related flags
        gatewayIP = parseArgs.gatewayIP
        dnsList = parseArgs.dnsList
        dnsIPList = parseArgs.dnsIPList

        # Check related flags
        if gatewayIP == None:
            print('Gateway IP address was not found, please specify using -g')
            raise SystemExit(1)

        if dnsList == None:
            print('DNS list was not found, please specify using -dnsl')
            raise SystemExit(1)

        if dnsIPList == None:
            print('DNS IP address list was not found, please specify using -dnsil')
            raise SystemExit(1)

        # Assign attack
        attack = attacks.ARPDNSSpoofing(victimIP, gatewayIP, dnsList, dnsIPList, interface) # TODO: Adapt script
    elif isSSLARPStrippingAttack:
        # Initialize related flags
        gatewayIP = parseArgs.gatewayIP

        # Check related flags
        if gatewayIP == None:
            print('Gateway IP address was not found, please specify using -g')
            raise SystemExit(1)

        # Assign attack
        attack = attacks.ARPSSLStripping(victimIP, gatewayIP, interface) # TODO: Adapt script
    else:
        # Prints the home screen
        printHome()
        
        # Ask questions to try to determine a chosen attack
        try:    
            attack = attackPrompt()
        except KeyboardInterrupt:
            printExit()
            raise SystemExit(1)

    # Start attack
    attack.execute()
