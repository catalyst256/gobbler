#!/usr/bin/env python

import socket
import re
import json

# Gobbler configuration file
# Welcome to Gobbler, the Scapy pcap parser and dump scripts
# Written by @catalyst256 / catalyst256@gmail.com

# Add some colouring for printing packets later
YELLOW = '\033[93m'
GREEN = '\033[92m'
END = '\033[0m'
RED = '\033[91m'

def splunk_shot_udp(splunk_server, splunk_port, s):
  # print GREEN + 'Uploading to Splunk via UDP' + END
  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((splunk_server, splunk_port))
    # print GREEN + 'Connected to Splunk server on %s via port %d' %(splunk_server, splunk_port) + END
    i = ', '.join("%s=%r" % (key,val) for (key,val) in s.iteritems())
    i = re.sub('\D{1,14}={', ' ', i)
    i = re.sub('[0-9]{1,2}={\D{5}', '', i)
    i = i.replace('{', '').replace('}','').replace('\'', '').replace(',', '').replace(': ', '=')
    sock.send(i)
    sock.close()
  except Exception, e:
    print e

def splunk_shot_tcp(splunk_server, splunk_port, s):
  # print GREEN + 'Uploading to Splunk via TCP' + END
  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((splunk_server, splunk_port))
    # print GREEN + 'Connected to Splunk server on %s via port %d' %(splunk_server, splunk_port) + END
    i = ', '.join("%s=%r" % (key,val) for (key,val) in s.iteritems())
    i = re.sub('\D{1,14}={', ' ', i)
    i = re.sub('[0-9]{1,2}={\D{6}=', '', i)
    i = i.replace('{', '').replace('}','').replace('\'', '').replace(',', '').replace(': ', '=')
    sock.send(i)
    sock.close()
  except Exception, e:
    print e

def json_dump(s):
  # print GREEN + 'Outputing to JSON' + END
  t = json.dumps(s, sort_keys=True,indent=2, separators=(',', ': '), ensure_ascii=False, encoding="utf-8")
  print t