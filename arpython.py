import argparse
import logging
import re
import sys
import threading
import Queue
import time

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
                    choices=['s', 'silent', 'n', 'normal', 'r', 'restore']
                    )

parser.add_argument('-d',
                    '--dns',
                    help="Launches a DNS spoofing attack against a victim, only works if and ARP spoofing attack has "
                         "already been executed. Can be executed together with an ARP poison attack. You can specify a "
                         "single IP as target, leave empty to target everything"
                    )

parser.add_argument('-p',
                    '--packets',
                    help="Specify a custom amount of packets for normal ARP attack, standard amount is 100",
                    )

parser.add_argument('-vi',
                    '--victim',
                    help="Use this flag to specify the IP address of the victim, for multiple addresses "
                         "seperate them by comma"
                    )

parser.add_argument('-gt',
                    '--gateway',
                    help="Use this flag to specify the IP address of the default gateway"
                    )

parser.add_argument('-vm',
                    '--victimmac',
                    help="Use this flag to specify the MAC address of the victim, for multiple separate"
                         "them by comma in order of victims"
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

parser.add_argument('-db',
                    '--debug',
                    help="Set the logging to debug mode",
                    action="store_const",
                    dest="loglevel",
                    const=logging.DEBUG,
                    default=logging.INFO
                    )

parser.add_argument('-vb',
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


# For interrupting the started threads
def threads_started(victims):
    try:
        while 1:
            try:
                msg = scan.get_queue()
                if msg == 'Done':
                    sys.exit(1)
                else:
                    scan.set_queue(msg)
            except Queue.Empty:
                time.sleep(.1)
    except KeyboardInterrupt:
        for i in range(victims):
            scan.set_queue('stop')


def main():
    args = parser.parse_args()
    logger.setLevel(args.loglevel)
    handler.setFormatter(formatter)
    handler.setLevel(args.loglevel)
    logger.addHandler(handler)

    # If gui was specified we will launch te GUI otherwise the program will run from the command line
    if args.gui:
        import gui
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
            for i in range(len(args.victim)):
                poison_thread = threading.Thread(target=scan.arp_poison_stealthy, args=(args.victim[i],
                                                                                        args.victimmac[i], args.gateway,
                                                                                        args.attackermac))
                poison_thread.start()

            threads_started(len(args.victim))
            sys.exit(1)
        elif args.arp == 'normal' or args.arp == 'n':
            args = check_arp(args)
            logging.info("Starting ARP Poison")
            for i in range(len(args.victim)):
                poison_thread = threading.Thread(target=scan.arp_poison, args=(args.victim[i], args.victimmac[i],
                                                                               args.gateway, args.gatewaymac,
                                                                               args.attackermac, args.packets))
                poison_thread.start()

            threads_started(len(args.victim))
            sys.exit(1)
        elif args.arp == 'restore' or args.arp == 'r':
            args = check_arp(args)
            logging.info("Starting ARP Restore")
            for i in range(len(args.victim)):
                restore_thread = threading.Thread(target=scan.arp_restore, args=(args.victim[i], args.victimmac[i],
                                                                                 args.gateway, args.gatewaymac))
                restore_thread.start()
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

    if "," in args.victim:
        args.victim.replace(" ", "")
        args.victim = args.victim.split(",")
    else:
        args.victim = [args.victim]

    if args.attackermac is not None and not re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$",
                                                     args.attackermac):
        logger.warn("Attacker MAC address is not a proper MAC address")
        sys.exit(1)

    if args.packets is not None and int(args.packets) < 0:
        logger.warn("Please make sure the amount of specified packets is larger than 0")
    elif args.packets is None:
        args.packets = 100
    else:
        args.packets = int(args.packets)

    if args.victimmac is None:
        logging.info("Grabbing the victims MAC address(es) since nothing was specified")
        args.victimmac = []
        for v in args.victim:
            args.victimmac.append(scan.get_mac(args.gateway, v))
    elif "," in args.victimmac:
        args.victimmac.replace(" ", "")
        args.victimmac = args.victim.split(",")
    else:
        args.victimmac = [args.victimmac]

    if args.gatewaymac is None:
        logging.info("Grabbing the gateways MAC address since nothing was specified")
        args.gatewaymac = scan.get_mac(args.victim, args.gateway)

    victims = len(args.victim)

    return args


if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)
elif __name__ == '__main__':
    main()
