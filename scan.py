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
def scan(net, interface, timeout=5):
    logger.info("Using scapy arping with %s on %s" % (net, interface))
    try:
        ans, unans = scapy.all.arping(net, iface=interface, timeout=timeout, verbose=True)
        for s, r in ans:
            line = r.src + " " + r.psrc
            logger.info(line)
    except socket.error as e:
        raise


scan("192.168.56.0/24", "enp0s3")