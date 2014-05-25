#!/usr/bin/env python

import socket
import re
from time import sleep
import json

# Welcome to Gobbler, the Scapy pcap parser and dump scripts
# Part of the sniffMyPackets suite http://www.sniffmypackets.net
# Written by @catalyst256 / catalyst256@gmail.com

# Add some colouring for printing packets later
YELLOW = '\033[93m'
GREEN = '\033[92m'
END = '\033[0m'
RED = '\033[91m'

def splunk_shot_udp(splunk_server, splunk_port, s):
  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((splunk_server, splunk_port))
    i = ','.join("%s=%r" % (key,val) for (key,val) in s.iteritems())
    i = re.sub('\w{1,15}={', '', i)
    i = re.sub('HTTP ', '', i)
    i = re.sub('[0-9]{1,2}={\D{5}', '', i)
    i = i.replace('{', '').replace('}','').replace(': ', '=').replace('\'', '')
    sock.send(i)
    sock.close()
    # sleep(2)
  except Exception, e:
    print e

def splunk_shot_tcp(splunk_server, splunk_port, s):
  # print GREEN + 'Uploading to Splunk via TCP' + END
  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((splunk_server, splunk_port))
    # print GREEN + 'Connected to Splunk server on %s via port %d' %(splunk_server, splunk_port) + END
    i = ', '.join("%s=%r" % (key,val) for (key,val) in s.iteritems())
    i = re.sub('\w{1,15}={', '', i)
    i = re.sub('HTTP ', '', i)
    i = re.sub('[0-9]{1,2}={\D{5}', '', i)
    i = i.replace('{', '').replace('}','').replace('\'', '').replace(': ', '=')
    sock.sendall(i)
  except Exception, e:
    print e
  sock.close()

def json_dump(s):
  # print GREEN + 'Outputing to JSON' + END
  t = json.dumps(s, sort_keys=True,indent=2, separators=(',', ': '), ensure_ascii=False, encoding="utf-8")
  print t