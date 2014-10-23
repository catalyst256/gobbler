#!/usr/bin/env python

import re

# Welcome to Gobbler, the Scapy pcap parser and dump scripts
# Part of the sniffMyPackets suite http://www.sniffmypackets.net
# Written by @catalyst256 / catalyst256@gmail.com


def exclude_layers(x, xname):
  # This is here to deal with the way that scapy stacks some of it's layers together which makes extracting them difficult.
  # Deal with IP packets that have "options"
  if xname == 'IP':
    if x['options'] != None:
      d = dict((k, v) for k, v in x.iteritems() if k not in 'options')
      return d
  # DNS packets
  if xname == 'DNS':
    if (x['qd'] or x['an'] or x['ar'] or x['ns']) != None:
      d = dict((k, v) for k, v in x.iteritems() if k not in ('qd', 'an', 'ns', 'ar'))
      return d
  # LLMNR are part multicast, part DNS, wholly a bitch to parse
  if xname == 'Link Local Multicast Node Resolution - Query':
    if (x['qd'] or x['an'] or x['ar'] or x['ns']) != None:
      d = dict((k, v) for k, v in x.iteritems() if k not in ('qd', 'an', 'ns', 'ar'))
      return d
  # Nasty SNMP Layers
  if xname == 'SNMP':
    if x['PDU'] != None:
      d = dict((k, v) for k, v in x.iteritems() if k not in 'PDU')
      d = str(d)
      d = re.sub('<ASN1_*\w{7}\[', '', d)
      d = re.sub(']>', '', d)
      s = eval(d)
      return s
  if xname == 'SNMPget':
    if x['varbindlist'] != None:
      d = dict((k, v) for k, v in x.iteritems() if k not in 'varbindlist')
      d = str(d)
      d = re.sub('<ASN1_*\w{3,7}\[', '', d)
      d = re.sub(']>', '', d)
      s = eval(d)
      return s
  if xname == 'SNMPvarbind':
      d = str(x)
      d = re.sub('<ASN1_*\w{3,7}\[', '', d)
      d = re.sub(']>', '', d)
      s = eval(d)
      return s
  if xname == 'SNMPresponse':
    if x['varbindlist'] != None:
      d = dict((k, v) for k, v in x.iteritems() if k not in 'varbindlist')
      d = str(d)
      d = re.sub('<ASN1_*\w{3,7}\[', '', d)
      d = re.sub(']>', '', d)
      s = eval(d)
      return s
  if xname == 'DHCP6 Client Identifier Option':
    if x['duid'] != None:
      d = dict((k, v) for k, v in x.iteritems() if k not in 'duid')
      return d
  if xname == 'IPv6 Extension Header - Hop-by-Hop Options Header':
    if x['options'] != None:
      d = dict((k,v) for k, v in x.iteritems() if k not in 'options')
      return d
  else:
    return x