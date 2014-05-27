#!/usr/bin/env python

# Welcome to Gobbler, the Scapy pcap parser and dump scripts
# Part of the sniffMyPackets suite http://www.sniffmypackets.net
# Written by @catalyst256 / catalyst256@gmail.com

import datetime
from http import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

END = '\033[0m'
RED = '\033[91m'

bind_layers(TCP, HTTP)

def packet_full(pkts, pcap):
  packet = {}
  count = 1
  try:
    for p in pkts:
      header = {"Buffer": {"timestamp": datetime.datetime.fromtimestamp(p.time).strftime('%Y-%m-%d %H:%M:%S.%f'), "packetnumber": count, "pcapfile": pcap}}
      packet.update(header)
      if p.haslayer(Ether):
        p_ether = {"Ether": {"ether_dst": p[Ether].dst, "ether_src": p[Ether].src, "ether_type": p[Ether].type}}
        packet.update(p_ether)
      if p.haslayer(ARP):
        p_arp = {"ARP": {"arp_hwtype": p[ARP].hwtype, "arp_ptype": p[ARP].ptype, 
                "arp_hwlen": p[ARP].hwlen, "arp_plen": p[ARP].plen, "arp_op": p[ARP].op, "arp_hwsrc": p[ARP].hwsrc,
                "arp_psrc": p[ARP].psrc, "arp_hwdst": p[ARP].hwdst, "arp_pdst": p[ARP].pdst}}
        packet.update(p_arp)
      if p.haslayer(IP):
        p_ip = {"IP": {"ip_version": p[IP].version, "ip_ihl": p[IP].ihl, "ip_proto": p[IP].proto,
                "ip_tos": p[IP].tos, "ip_len": p[IP].len, "ip_id": p[IP].id, "ip_flags": p[IP].flags,
                "ip_frag": p[IP].frag, "ip_ttl": p[IP].ttl, "ip_chksum": p[IP].chksum, "ip_src": p[IP].src,
                "ip_dst": p[IP].dst, "ip_options": p[IP].options}}
        packet.update(p_ip)
      if p.haslayer(TCP):
        p_tcp = {"TCP": {"tcp_sport": p[TCP].sport, "tcp_dport": p[TCP].dport, "tcp_seq": p[TCP].seq,
                "tcp_ack": p[TCP].ack, "tcp_dataofs": p[TCP].dataofs, "tcp_reserved": p[TCP].reserved,
                "tcp_flags": p[TCP].flags, "tcp_window": p[TCP].window, "tcp_chksum": p[TCP].chksum,
                "tcp_urgptr": p[TCP].urgptr, "tcp_options": p[TCP].options}}
        packet.update(p_tcp)
      if p.haslayer(UDP):
        p_udp = {"UDP": {"udp_len": p[UDP].len, "udp_sport": p[UDP].sport, "udp_dport": p[UDP].dport,
                "udp_chksum": p[UDP].chksum}}
        packet.update(p_udp)
      if p.haslayer(DNS):
        p_dns = {"DNS": {"dns_id": p[DNS].id, "dns_qr": p[DNS].qr, "dns_opcode": p[DNS].opcode, "dns_aa": p[DNS].aa,
                "dns_tc": p[UDP].tc, "dns_rd": p[UDP].rd, "dns_ra": p[UDP].ra, "dns_z": p[UDP].z, "dns_ad": p[UDP].ad,
                "dns_cd": p[UDP].cd, "dns_rcode": p[UDP].rcode}}
        packet.update(p_dns)
      if p.haslayer(DNSQR):
        p_dnsqr = {"DNSQR": {"dnsqr_qname": p[DNSQR].qname, "dnsqr_qtype": p[DNSQR].qtype, "dnsqr_qclass": p[DNSQR].qclass}}
        packet.update(p_dnsqr)
      if p.haslayer(DNSRR) and p.getlayer(DNS).ancount != 1:
        p_dnsrr = {}
        a_count = p[DNS].ancount
        i = 4 + a_count
        while i != 4:
          p_dnsrr[i] = {"DNSRR": {"dnsrr_rrname": p[0][i].rrname, "dnsrr_rdata": p[0][i].rdata, "dnsrr_type": p[0][i].type,
                    "dnsrr_rclass": p[0][i].rclass, "dnsrr_ttl": p[0][i].ttl, "dnsrr_rdlen": p[0][i].rdlen}}
          p_dnsrr.update(p_dnsrr)
          i -= 1
        packet.update(p_dnsrr)
      else:
        if p.haslayer(DNSRR):
          p_dnsrr = {"DNSRR": {"dnsrr_rrname": p[DNSRR].rrname, "dnsrr_rdata": p[DNSRR].rdata, "dnsrr_type": p[DNSRR].type,
                    "dnsrr_rclass": p[DNSRR].rclass, "dnsrr_ttl": p[DNSRR].ttl, "dnsrr_rdlen": p[DNSRR].rdlen}}
          packet.update(p_dnsrr)
      if p.haslayer(ICMP):
        p_icmp = {"ICMP": {"icmp_type": p[ICMP].type, "icmp_code": p[ICMP].code, "icmp_chksum": p[ICMP].chksum,
                  "icmp_id": p[ICMP].id, "icmp_seq": p[ICMP].seq}}
        packet.update(p_icmp)
      if p.haslayer(Raw):
        p_raw = {"Raw": {"raw_load": p[Raw].load}}
        packet.update(p_raw)
      if p.haslayer(HTTPrequest):
        p_http_req = {"HTTPRequest": {"http_req_method": p[HTTPrequest].Method, "http_req_host": p[HTTPrequest].Host, "http_req_useragent": p[HTTPrequest].UserAgent,
                      "http_req_accept": p[HTTPrequest].Accept, "http_req_acceptlanguage": p[HTTPrequest].AcceptLanguage, "http_req_acceptencoding": p[HTTPrequest].AcceptEncoding,
                      "http_req_acceptcharset": p[HTTPrequest].AcceptCharset, "http_req_referer": p[HTTPrequest].Referer, "http_req_authorization": p[HTTPrequest].Authorization,
                      "http_req_expect": p[HTTPrequest].Expect, "http_req_from": p[HTTPrequest].From, "http_req_ifmatch": p[HTTPrequest].IfMatch, "http_req_te": p[HTTPrequest].TE,
                      "http_req_ifmodifiedsince": p[HTTPrequest].IfModifiedSince, "http_req_ifnonematch": p[HTTPrequest].IfNoneMatch, "http_req_ifrange": p[HTTPrequest].IfRange,
                      "http_req_ifunmodifiedsince": p[HTTPrequest].IfUnmodifiedSince, "http_req_maxforwards": p[HTTPrequest].MaxForwards, "http_req_proxyauthorization": p[HTTPrequest].ProxyAuthorization,
                      "http_req_range": p[HTTPrequest].Range}}
        packet.update(p_http_req)
      if p.haslayer(HTTPresponse):
        p_http_resp = {"HTTPResponse": {"http_res_statusline": p[HTTPresponse].StatusLine, "http_res_acceptranges": p[HTTPresponse].AcceptRanges, "http_res_age": p[HTTPresponse].Age,
                      "http_res_etag": p[HTTPresponse].ETag, "http_res_location": p[HTTPresponse].Location, "http_res_proxyauthenticate": p[HTTPresponse].ProxyAuthenticate,
                      "http_res_retryafter": p[HTTPresponse].RetryAfter, "http_res_server": p[HTTPresponse].Server, "http_res_vary": p[HTTPresponse].Vary, "http_res_wwwauthenticate": p[HTTPresponse].WWWAuthenticate}}
        packet.update(p_http_resp)
      if p.haslayer(TCPerror):
        p_tcp_icmp = {"TCPinICMP": {"tcp_icmp_sport": p[TCPerror].sport, "tcp_icmp_dport": p[TCPerror].dport, "tcp_icmp_seq": p[TCPerror].seq, "tcp_icmp_ack": p[TCPerror].ack,
                      "tcp_icmp_dataofs": p[TCPerror].dataofs, "tcp_icmp_reserved": p[TCPerror].reserved, "tcp_icmp_flags": p[TCPerror].flags, "tcp_icmp_window": p[TCPerror].window,
                      "tcp_icmp_chksum": p[TCPerror].chksum, "tcp_icmp_urgptr": p[TCPerror].urgptr, "tcp_icmp_options": p[TCPerror].options}}
        packet.update(p_tcp_icmp)
      if p.haslayer(UDPerror):
        p_udp_icmp = {"UDPinICMP": {"udp_icmp_sport": p[UDPerror].sport, "udp_icmp_dport": p[UDPerror].dport, "udp_icmp_len": p[UDPerror].len, "udp_icmp_chksum": p[UDPerror].chksum}}
        packet.update(p_udp_icmp)
      if p.haslayer(NTP):
        p_ntp = {"NTP": {"ntp_leap": p[NTP].leap, "ntp_version": p[NTP].version, "ntp_mode": p[NTP].mode, "ntp_stratum": p[NTP].stratum, "ntp_poll": p[NTP].poll,
                 "ntp_precision": p[NTP].precision, "ntp_delay": p[NTP].delay, "ntp_dispersion": p[NTP].dispersion, "ntp_id": p[NTP].id, "ntp_ref": p[NTP].ref, "ntp_orig": p[NTP].orig,
                 "ntp_recv": p[NTP].recv, "ntp_sent": p[NTP].sent}}
        packet.update(p_ntp)
      count += 1
      yield packet
      packet.clear()
  except Exception, e:
    print e
    pass

def packet_summary(pkts, pcap):
  packet = {}
  count = 1
  try:
    for p in pkts:
      p_header = {"header": {"packet_len": p[0].len, "timestamp": datetime.datetime.fromtimestamp(p.time).strftime('%Y-%m-%d %H:%M:%S.%f'), "packetnumber": count, "pcapfile": pcap}}
      packet.update(p_header)
      if p.haslayer(IP):
        p_ip = {"IP": {"ip_src": p[IP].src, "ip_dst": p[IP].dst, "ip_ttl": p[IP].ttl}}
        packet.update(p_ip)
      p_proto = {"protocol": {"proto": p[0][2].name}}
      packet.update(p_proto)
      count += 1
      yield packet
      packet.clear()
  except Exception, e:
    print e
    pass



