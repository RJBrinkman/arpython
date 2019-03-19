import argparse
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
                    action="store_true")

parser.add_argument('-a',
                    '--arp',
                    help="Launches an ARP spoofing attack against a victim chose from silent (s) or normal (n)",
                    choices=['s', 'silent', 'n', 'normal'])

parser.add_argument('-s',
                    '--scan',
                    help="Scans which network interfaces are available and prints the information",
                    action="store_true")


if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)

args = parser.parse_args()

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
