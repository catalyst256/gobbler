#!/usr/bin/env python

import socket
import re
import json
import pymongo
import requests
from collections import OrderedDict

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
    i = re.sub('\w*.\w*.\w*\[\d*\]={', ', ', i)
    i = re.sub('\w{1,}={', '', i)
    i = i.replace('{', '').replace('}','').replace(': ', '=').replace('\'', '').replace(' , ', ' ')
    sock.send(i)
    sock.close()
  except Exception, e:
    print RED + str(e) + END

def splunk_shot_tcp(splunk_server, splunk_port, s):
  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((splunk_server, splunk_port))
    i = ', '.join("%s=%r" % (key,val) for (key,val) in s.iteritems())
    i = re.sub('\w*.\w*.\w*\[\d*\]={', ', ', i)
    i = re.sub('\w{1,}={', '', i)
    i = i.replace('{', '').replace('}','').replace('\'', '').replace(': ', '=').replace(' , ', ' ')
    sock.send(i)
  except Exception, e:
    print RED + str(e) + END
  sock.close()

def json_dump(s):
  t = json.dumps(s, indent=2, separators=(',', ': '), ensure_ascii=False, encoding="utf-8")
  print t

def elk_dump(elkserver, elkport, elkindex, s):
  try:
    e = json.loads(json.dumps(s, indent=2, separators=(',', ': '), ensure_ascii=False, encoding="latin-1"))
    v = OrderedDict(json.loads(json.dumps(s, encoding="latin-1")))
    elk_type = e['Buffer']['pcapfile']
    elk_id = e['Buffer']['packetnumber']
    url = 'http://' + str(elkserver) + ':' + str(elkport) + '/' + str(elkindex) + '/' + str(elk_type) + '/' + str(elk_id)
    r = requests.post(url, data=v)
  except Exception, e:
    print RED + str(e) + END

def mongo_dump(mongo_server, mongo_port, mongo_db, mongo_collection, s):
  try:
    connection = pymongo.MongoClient(mongo_server, mongo_port)
    db = connection[mongo_db]
    coll = db[mongo_collection]
  except pymongo.errors.ConnectionFailure, e:
    print RED + "Could not connect to MongoDB: %s" % e + END
  try:
    v = OrderedDict(json.loads(json.dumps(s, encoding="latin-1")))
    coll.insert(v)
  except Exception, e:
    print e
    pass