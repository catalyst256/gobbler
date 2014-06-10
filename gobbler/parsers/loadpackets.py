#!/usr/bin/env python

# Gobbler configuration file

# Welcome to Gobbler, the Scapy pcap parser and dump scripts
# Part of the sniffMyPackets suite http://www.sniffmypackets.net
# Written by @catalyst256 / catalyst256@gmail.com

import logging
import os
import sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import rdpcap
from scapy.error import Scapy_Exception


# Add some colouring for printing packets later
YELLOW = '\033[93m'
GREEN = '\033[92m'
END = '\033[0m'
RED = '\033[91m'

def loadpackets(pcap):
  if os.path.isfile(pcap):
    print GREEN + 'Loading pcap file: ' + pcap + END
    try:
      p = rdpcap(pcap)
      print YELLOW + 'Number of packets: ' + str(len(p)) + END
      return p
    except Scapy_Exception as msg:
      print RED + str(msg) + END
      sys.exit(0)
  else:
    print RED + 'ERROR: You sure that\'s the right file location???: [' + pcap + ']' + END
  