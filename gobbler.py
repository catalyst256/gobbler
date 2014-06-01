#!/usr/bin/env python

# Welcome to Gobbler, the Scapy pcap parser and dump scripts
# Part of the sniffMyPackets suite http://www.sniffmypackets.net
# Written by @catalyst256 / catalyst256@gmail.com

import sys
import optparse
from ConfigParser import SafeConfigParser
from parsers.loadpackets import loadpackets
from parsers.packetParser import *
from uploaders.uploaders import *

# Add some colouring for printing packets later
YELLOW = '\033[93m'
GREEN = '\033[92m'
END = '\033[0m'
RED = '\033[91m'

# Load the gobbler.conf file
conf = SafeConfigParser()
conf.read('gobbler.conf')

splunk_server = conf.get('splunk', 'server').strip('\'')
splunk_port = int(conf.get('splunk', 'port'))
mongo_server = conf.get('mongodb', 'server').strip('\'')
mongo_port = int(conf.get('mongodb', 'port'))
mongo_db = conf.get('mongodb', 'db').strip('\'')
mongo_collection = conf.get('mongodb', 'collection').strip('\'')

def main():
  print GREEN + "Welcome to Gobbler, the pcap file muncher & regurgitater. Written by @catalyst256"  + END
  parser = optparse.OptionParser(RED + "Usage: ./gobbler.py -p <pcap file> -u <upload> -s <summary>\nExample: ./gobbler.py -p test.pcap -u splunk -s light"+ END)
  parser.add_option('-p', dest='pcapFile', type='string', help='specify pcap filename')
  parser.add_option('-u', dest='upload', type='string', help='specify upload method (i.e. splunk or json)')
  parser.add_option('-s', dest='summary', type='string', help='specify summary level (full/light)')
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
  summary = ''
  if options.summary == None:
    summary = 'full'
  else:
    summary = options.summary
  # Work out the listener for splunk and call the function
  if upload == 'splunk':
    proto = conf.get('splunk', 'protocol').strip('\'')
    if proto == 'tcp':
      if summary == 'full':
        pkts = loadpackets(pcap)
        x = find_layers(pkts, pcap)
        print GREEN + 'Uploading to Splunk via TCP - Full Details' + END
        for s in x:
          splunk_shot_tcp(splunk_server, splunk_port, s)
        print GREEN + 'Upload Complete' + END
      if summary == 'light':
        pkts = loadpackets(pcap)
        x = packet_summary(pkts, pcap)
        print GREEN + 'Uploading to Splunk via TCP - Summary Details' + END
        for s in x:
          splunk_shot_tcp(splunk_server, splunk_port, s)
        print GREEN + 'Upload Complete' + END
    if proto == 'udp':
      if summary == 'full':
        pkts = loadpackets(pcap)
        x = find_layers(pkts, pcap)
        print GREEN + 'Uploading to Splunk via UDP - Full Details' + END
        for s in x:
          splunk_shot_udp(splunk_server, splunk_port, s)
        print GREEN + 'Upload Complete' + END
      if summary == 'light':
        pkts = loadpackets(pcap)
        x = packet_summary(pkts, pcap)
        print GREEN + 'Uploading to Splunk via UDP - Summary Details' + END
        for s in x:
          splunk_shot_udp(splunk_server, splunk_port, s)
        print GREEN + 'Upload Complete' + END
  if upload == 'json':
    if summary == 'full':
      print GREEN + 'Outputing to JSON - Full Details' + END
      pkts = loadpackets(pcap)
      x = find_layers(pkts, pcap)
      for s in x:
        # print s
        json_dump(s)
      print GREEN + 'Upload Complete' + END
    if summary == 'light':
      print GREEN + 'Outputing to JSON - Summary Details' + END
      pkts = loadpackets(pcap)
      x = packet_summary(pkts, pcap)
      for s in x:
        json_dump(s)
      print GREEN + 'Upload Complete' + END
  if upload == 'mongo':
    print GREEN + 'Outputting to MongoDB' + END
    pkts = loadpackets(pcap)
    x = find_layers(pkts, pcap)
    for s in x:
      mongo_dump(mongo_server, mongo_port, mongo_db, mongo_collection, s)
  if upload == 'screen':
    print GREEN + 'Outputting to Screen' + END
    pkts = loadpackets(pcap)
    packet_print(pkts, pcap)
  
if __name__ == "__main__":
  main()