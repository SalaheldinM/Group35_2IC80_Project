from arp_poisoning import *
from dns_spoofing import *
from ssl_stripping import *

def main():
    print('Pick a number for an attack: \033[0m')
    print('1. ARP Poisoning Attack')
    print('2. DNS Spoofing Attack')
    print('3. SSL Stripping Attack')
    choice = input()
    if choice == '1':
        runARPPoisoning()
    elif choice == '2':
        runDNSSpoofing()
    elif choice == '3':
        runSSLStripping()
    else:
        print('Please pick a proper option!')
        main()

if __name__ == "__main__":
    main()