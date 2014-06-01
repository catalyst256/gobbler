#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# http://tools.ietf.org/html/rfc2616
# Author : Steeve Barbeau
# Twitter : @steevebarbeau
# Blog : steeve-barbeau.blogspot.com

import logging
import re
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import bind_layers, interact, Packet, StrField, TCP


class HTTPrequest(Packet):
	name = "HTTP Request"
	http_methods = "^(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT)"
	fields_desc=[StrField("Method", None, fmt="H"),
				StrField("Host", None, fmt="H"),
				StrField("UserAgent", None, fmt="H"),
				StrField("Accept", None, fmt="H"),
				StrField("AcceptLanguage", None, fmt="H"),
				StrField("AcceptEncoding", None, fmt="H"),
				StrField("AcceptCharset", None, fmt="H"),
				StrField("Referer", None, fmt="H"),
				StrField("Authorization", None, fmt="H"),
				StrField("Expect", None, fmt="H"),
				StrField("From", None, fmt="H"),
				StrField("IfMatch", None, fmt="H"),
				StrField("IfModifiedSince", None, fmt="H"),
				StrField("IfNoneMatch", None, fmt="H"),
				StrField("IfRange", None, fmt="H"),
				StrField("IfUnmodifiedSince", None, fmt="H"),
				StrField("MaxForwards", None, fmt="H"),
				StrField("ProxyAuthorization", None, fmt="H"),
				StrField("Range", None, fmt="H"),
				StrField("TE", None, fmt="H")]


	def do_dissect(self, s):
		fields_rfc = ["Method", "Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Accept-Charset", "Referer", "Authorization", "Expect", "From", "If-Match", "If-Modified-Since", "If-None-Match", "If-Range", "If-Unmodified-Since", "Max-Forwards", "Proxy-Authorization", "Range", "TE"]
		
		a=s.split("\r\n")
		obj = self.fields_desc[:]
		obj.reverse()
		fields_rfc.reverse()
		while obj:
			f = obj.pop()
			g = fields_rfc.pop()
			for x in a:
				if(g=="Method"):
					prog=re.compile(self.http_methods)
				else:
					prog=re.compile(g+":", re.IGNORECASE)
				result=prog.search(x)
				if result:
					self.setfieldval(f.name, x+'\r\n')
					a.remove(x)
		return '\r\n'+"".join(a)


class HTTPresponse(Packet):
	name = "HTTP Response"
	fields_desc=[StrField("StatusLine", None, fmt="H"),
				StrField("AcceptRanges", None, fmt="H"),
				StrField("Age", None, fmt="H"),
				StrField("ETag", None, fmt="H"),
				StrField("Location", None, fmt="H"),
				StrField("ProxyAuthenticate", None, fmt="H"),
				StrField("RetryAfter", None, fmt="H"),
				StrField("Server", None, fmt="H"),
				StrField("Vary", None, fmt="H"),
				StrField("WWWAuthenticate", None, fmt="H")]

	def do_dissect(self, s):
		fields_rfc = ["Status-Line","Accept-Ranges","Age","ETag","Location","Proxy-Authenticate", "Retry-After", "Server", "Vary", "WWW-Authenticate"]
		
		a=s.split("\r\n")
		obj = self.fields_desc[:]
		obj.reverse()
		fields_rfc.reverse()
		while obj:
			f = obj.pop()
			g = fields_rfc.pop()
			for x in a:
				if(g=="Status-Line"):
					prog=re.compile("^HTTP/((0\.9)|(1\.0)|(1\.1))\ [0-9]{3}.*")
				else:
					prog=re.compile(g+":", re.IGNORECASE)
				result=prog.search(x)
				if result:
					self.setfieldval(f.name, x+'\r\n')
					a.remove(x)
		return '\r\n'+"".join(a)


class HTTP(Packet):
	name="HTTP"
	fields_desc = [StrField("CacheControl", None, fmt="H"),
					StrField("Connection", None, fmt="H"),
					StrField("Date", None, fmt="H"),
					StrField("Pragma", None, fmt="H"),
					StrField("Trailer", None, fmt="H"),
					StrField("TransferEncoding", None, fmt="H"),
					StrField("Upgrade", None, fmt="H"),
					StrField("Via", None, fmt="H"),
					StrField("Warning", None, fmt="H"),
					StrField("KeepAlive", None, fmt="H"),
					StrField("Allow", None, fmt="H"),
					StrField("ContentEncoding", None, fmt="H"),
					StrField("ContentLanguage", None, fmt="H"),
					StrField("ContentLength", None, fmt="H"),
					StrField("ContentLocation", None, fmt="H"),
					StrField("ContentMD5", None, fmt="H"),
					StrField("ContentRange", None, fmt="H"),
					StrField("ContentType", None, fmt="H"),
					StrField("Expires", None, fmt="H"),
					StrField("LastModified", None, fmt="H")]

	def do_dissect(self, s):
		fields_rfc = ["Cache-Control", "Connection", "Date", "Pragma", "Trailer", "Transfer-Encoding", "Upgrade", "Via", "Warning", "Keep-Alive", "Allow", "Content-Encoding", "Content-Language", "Content-Length", "Content-Location", "Content-MD5", "Content-Range", "Content-Type", "Expires", "Last-Modified"]
		
		a=s.split("\r\n")
		obj = self.fields_desc[:]
		obj.reverse()
		fields_rfc.reverse()
		while obj:
			f = obj.pop()
			g = fields_rfc.pop()
			for x in a:
				prog=re.compile(g+":", re.IGNORECASE)
				result=prog.search(x)
				if result:
					self.setfieldval(f.name, x+'\r\n')
					a.remove(x)
		return "\r\n".join(a)
	
	def guess_payload_class(self, payload):
		prog=re.compile("^(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT)")
		result=prog.search(payload)
		if result:
			return HTTPrequest
		else:
			prog=re.compile("^HTTP/((0\.9)|(1\.0)|(1\.1))\ [0-9]{3}.*")
			result=prog.search(payload)
			if result:
				return HTTPresponse
		return Packet.guess_payload_class(self, payload)	
	