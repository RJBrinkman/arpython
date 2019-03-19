import argparse
import logging
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

parser.add_argument('-s',
                    '--scan',
                    help="Scans which network interfaces are available and prints the information",
                    action="store_true"
                    )

parser.add_argument('-d',
                    '--debug',
                    help="Set the logging to debug mode",
                    action="store_const",
                    dest="loglevel",
                    const=logging.DEBUG,
                    default=logging.WARNING
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
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


def main():
    args = parser.parse_args()
    logger.setLevel(args.loglevel)
    handler.setFormatter(formatter)
    handler.setLevel(args.loglevel)
    logger.addHandler(handler)

    logger.error('main')

    # If gui was specified we will launch te GUI otherwise the program will run from the command line
    if args.gui:
        gui.run()
    else:
        # A scan of the network has been requested
        if args.scan:
            interfaces = scan.get_interfaces()
            print("The following interfaces are present: \n")
            for i in interfaces:
                print(i)
        elif args.arp == 'silent' or args.arp == 's':
            print('hi')
        elif args.arp == 'normal' or args.arp == 'n':
            print('Does normaal joh')


if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)
elif __name__ == '__main__':
    main()
