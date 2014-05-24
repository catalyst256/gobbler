#!/usr/bin/env python

# Welcome to Gobbler, the Scapy pcap parser and dump scripts
# Written by @catalyst256 / catalyst256@gmail.com

import sys
import logging
import optparse
from ConfigParser import SafeConfigParser
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from parsers.http import *
from parsers.loadpackets import loadpackets
from parsers.packetParser import parsePacket
from uploaders.uploaders import *
from scapy.all import *

# Add some colouring for printing packets later
YELLOW = '\033[93m'
GREEN = '\033[92m'
END = '\033[0m'
RED = '\033[91m'

# Lets do the important stuff first
bind_layers(TCP, HTTP) # Binds the HTTP layers from the parser to TCP layers in Scapy so we can reference them

# Load the gobbler.conf file
conf = SafeConfigParser()
conf.read('gobbler.conf')

splunk_server = conf.get('splunk', 'server').strip('\'')
splunk_port = int(conf.get('splunk', 'port'))

def main():
  print GREEN + "Welcome to Gobbler, the pcap file muncher & regurgitater. Written by @catalyst256"  + END
  parser = optparse.OptionParser(RED + "Usage: ./gobbler.py -p <pcap file> -u <upload> \nExample: ./gobbler.py -p test.pcap -u splunk" + END)
  parser.add_option('-p', dest='pcapFile', type='string', help='specify pcap filename')
  parser.add_option('-u', dest='upload', type='string', help='specify upload method (i.e. splunk or json)')
  (options, args) = parser.parse_args()
  # Check options have been used and if they haven't exit with error
  if options.pcapFile == None:
    print parser.usage
    exit(0)
  pcap = options.pcapFile
  if options.upload == None:
    print parser.usage
    exit(0)
  upload = options.upload
  # Work out the listener for splunk and call the function
  if upload == 'splunk':
    proto = conf.get('splunk', 'protocol').strip('\'')
    if proto == 'tcp':
      pkts = loadpackets(pcap)
      x = parsePacket(pkts, pcap)
      for s in x:
        splunk_shot_tcp(splunk_server, splunk_port, s)
    if proto == 'udp':
      pkts = loadpackets(pcap)
      x = parsePacket(pkts, pcap)
      for s in x:
        splunk_shot_udp(splunk_server, splunk_port, s)
  if upload == 'json':
    print GREEN + 'Outputing to JSON' + END
    pkts = loadpackets(pcap)
    x = parsePacket(pkts, pcap)
    for s in x:
      json_dump(s)
  
if __name__ == "__main__":
  main()