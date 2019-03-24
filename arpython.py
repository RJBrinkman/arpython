import argparse
import logging
import re
import sys
import gui
import scan


parser = argparse.ArgumentParser(description='''
           _____  _____       _   _                 
     /\   |  __ \|  __ \     | | | |                
    /  \  | |__) | |__) |   _| |_| |__   ___  _ __  
   / /\ \ |  _  /|  ___/ | | | __| '_ \ / _ \| '_ \ 
  / ____ \| | \ \| |   | |_| | |_| | | | (_) | | | |
 /_/    \_\_|  \_\_|    \__, |\__|_| |_|\___/|_| |_|
                         __/ |                      
                        |___/ 
                        
An all-round ARP tool written in Python for the Lab on Offensive Computer Security course.                      
''',
                                 usage='Use "%(prog)s --help" for more information',
                                 formatter_class=argparse.RawTextHelpFormatter)

parser.add_argument('-g',
                    '--gui',
                    help="Launches the tools gui, TKinter needs to be installed for this",
                    action="store_true"
                    )

parser.add_argument('-a',
                    '--arp',
                    help="Launches an ARP spoofing attack against a victim chose from silent (s) or normal (n)",
                    choices=['s', 'silent', 'n', 'normal']
                    )

parser.add_argument('-vi',
                    '--victim',
                    help="Use this flag to specify the IP address of the victim"
                    )

parser.add_argument('-gt',
                    '--gateway',
                    help="Use this flag to specify the IP address of the default gateway"
                    )

parser.add_argument('-vm',
                    '--victimmac',
                    help="Use this flag to specify the MAC address of the victim"
                    )

parser.add_argument('-gm',
                    '--gatewaymac',
                    help="Use this flag to specify the MAC address of the default gateway"
                    )

parser.add_argument('-am',
                    '--attackermac',
                    help="Use this flag to specify the MAC address of the attacker if you "
                         "want one different from your machine"
                    )

parser.add_argument('-s',
                    '--scan',
                    help="Scans which network interfaces are available and prints the information",
                    action="store_true"
                    )

parser.add_argument('-si',
                    '--scaniface',
                    help="Scans a given interface for active IP and MAC addresses. "
                         "Just specifying the IP address is enough"
                    )

parser.add_argument('-d',
                    '--debug',
                    help="Set the logging to debug mode",
                    action="store_const",
                    dest="loglevel",
                    const=logging.DEBUG,
                    default=logging.INFO
                    )

parser.add_argument('-v',
                    '--verbose',
                    help="Set the logging to verbose mode",
                    action="store_const",
                    dest="loglevel",
                    const=logging.INFO
                    )


logger = logging.getLogger()
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
file_handler = logging.FileHandler(r'./log.txt')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.addHandler(handler)


def main():
    args = parser.parse_args()
    logger.setLevel(args.loglevel)
    handler.setFormatter(formatter)
    handler.setLevel(args.loglevel)
    logger.addHandler(handler)

    # If gui was specified we will launch te GUI otherwise the program will run from the command line
    if args.gui:
        gui.run()
    else:
        # A scan of the network has been requested
        if args.scan:
            logger.info("Scanning for interfaces")
            interfaces = scan.get_interfaces()
            logger.info("The following interfaces are present: \n")
            for i in interfaces:
                logger.info(i)
        elif args.arp == 'silent' or args.arp == 's':
            args = check_arp(args)
            logging.info("Starting silent ARP Poison")
            scan.arp_poison_stealthy(router_ip=args.gateway, router_mac=args.gatewaymac, victim_ip=args.victim,
                                     victim_mac=args.victimmac)
        elif args.arp == 'normal' or args.arp == 'n':
            args = check_arp(args)
            logging.info("Starting ARP Poison")
            scan.arp_poison(router_ip=args.gateway, router_mac=args.gatewaymac, victim_ip=args.victim,
                            victim_mac=args.victimmac)
        elif args.scaniface:
            # Grab the IP's and MAC addresses
            logger.info("Matching the interface")
            interfaces = scan.get_interfaces()
            interfaces = [s for s in interfaces if re.match(args.scaniface, s)]
            if len(interfaces) == 1:
                logger.info("Scanning for devices")
                s = interfaces[0].split(", ")
                scan.scan(net=s[0], interface=s[1])
            else:
                logger.warn("Cannot find one interface that matches, you can use the -s or --scan "
                            "flag to list interfaces")
                sys.exit(1)


# Checks if the arp argument is valid
def check_arp(args):
    if args.victim is None or args.gateway is None:
        logger.warn("For the ARP Poisoning to work at least the --victim and --gateway flags should be set. "
                    "The mac flags are optional.")
        sys.exit(1)

    if args.victimmac is None:
        logging.info("Grabbing the victims MAC address since nothing was specified")
        args.victimmac = scan.get_mac(args.gateway, args.victim)

    if args.gatewaymac is None:
        logging.info("Grabbing the gateways MAC address since nothing was specified")
        args.gatewaymac = scan.get_mac(args.victim, args.gateway)

    return args


if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)
elif __name__ == '__main__':
    main()
