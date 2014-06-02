#!/usr/bin/env python

# Welcome to Gobbler, the Scapy pcap parser and dump scripts
# Part of the sniffMyPackets suite http://www.sniffmypackets.net
# Written by @catalyst256 / catalyst256@gmail.com

import datetime
from gobbler.layers.http import *
from gobbler.layers.BadLayers import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from collections import OrderedDict

END = '\033[0m'
RED = '\033[91m'
GREEN = '\033[92m'

bind_layers(TCP, HTTP)

def rename_layer(x, n):
  n = n.lower().replace(' ', '_') + '_'
  return dict((n+k.lower(),f(v) if hasattr(v,'keys') else v) for k,v in x.items())

def find_layers(pkts, pcap):
  packet = OrderedDict()
  count = 1
  try:
    for p in pkts:
      header = {"Buffer": {"timestamp": datetime.datetime.fromtimestamp(p.time).strftime('%Y-%m-%d %H:%M:%S.%f'), "packetnumber": count, "pcapfile": pcap}}
      packet.update(header)  
      counter = 0
      while True:
        layer = p.getlayer(counter)
        if (layer != None):
          i = int(counter)
          x = p[0][i].fields
          t = exclude_layers(x, layer.name)
          s = rename_layer(t, layer.name)
          v = '{"[' + str(i) + ']' + layer.name + '":' + str(s) + '}'
          s = eval(v)
          packet.update(s)
        else:
          break
        counter += 1
      count += 1
      yield packet
      packet.clear()
  except Exception as e:
    print RED + 'Error within packet: ' + str(count) + ', the error was: ' + str(e) + END

def packet_summary(pkts, pcap):
  packet = OrderedDict()
  count = 1
  try:
    for p in pkts:
      if p.haslayer(IP):
        p_header = {"Buffer": {"timestamp": datetime.datetime.fromtimestamp(p.time).strftime('%Y-%m-%d %H:%M:%S.%f'), "packet_len": p[0].len, "packetnumber": count, "pcapfile": pcap}}
        packet.update(p_header)
        p_ip = {"IP": {"ip_src": p[IP].src, "ip_dst": p[IP].dst, "ip_ttl": p[IP].ttl}}
        packet.update(p_ip)
        p_proto = {"Protocol": {"proto": p[0][2].name}}
        packet.update(p_proto)
        count += 1
      yield packet
      packet.clear()
  except Exception, e:
    print e
    pass

def packet_print(pkts, pcap):
  count = 1
  try:
    for p in pkts:
      if p.haslayer(IP):
        packet = str(count), str(datetime.datetime.fromtimestamp(p.time).strftime('%Y-%m-%d %H:%M:%S')), str(p[IP].src), str(p[IP].dst), str(p[0][2].name), str(p[IP].len) 
        print GREEN + str(packet).replace(')', '').replace('(', '').replace('\'', '') + END
      count += 1
  except Exception, e:
    print e
    pass


