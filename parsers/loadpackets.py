#!/usr/bin/env python

# Gobbler configuration file

# Welcome to Gobbler, the Scapy pcap parser and dump scripts
# Part of the sniffMyPackets suite http://www.sniffmypackets.net
# Written by @catalyst256 / catalyst256@gmail.com

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import rdpcap


# Add some colouring for printing packets later
YELLOW = '\033[93m'
GREEN = '\033[92m'
END = '\033[0m'
RED = '\033[91m'

def loadpackets(pcap):
  print GREEN + 'Loading pcap file: ' + pcap + END
  p = rdpcap(pcap)
  print YELLOW + 'Number of packets: ' + str(len(p)) + END
  return p
  