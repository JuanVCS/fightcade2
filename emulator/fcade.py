#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# UDP Hole Punching wrapper proxy for FightCade2
#
#  (c) 2014-2017 Pau Oliva Fora (@pof)
#  (c) 2010 Koen Bollen <meneer koenbollen nl>
#  (C) 2009 Dmitriy Samovskiy, http://somic.org
#   https://gist.github.com/koenbollen/464613
#   https://gist.github.com/somic/224795
#
# puncher function License: Apache License, Version 2.0
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#

import sys
import os
import socket
from select import select
from subprocess import Popen, PIPE
import struct
import random
import threading
import Queue
import time
import traceback
import logging
import platform
import hashlib
import glob
import json
import re
import urllib
import urllib2

def bytes2addr( bytes ):
	"""Convert a hash to an address pair."""
	if len(bytes) != 6:
		raise ValueError, "invalid bytes"
	host = socket.inet_ntoa( bytes[:4] )
	port, = struct.unpack( "H", bytes[-2:] )
	return host, port


def start_fba(args):

	FBA="fcadefba.exe"

	# try to guess install directory:
	dirtest = os.path.abspath(os.path.dirname(sys.argv[0]))
	if not os.path.isfile(os.path.join(dirtest,FBA)):
		dirtest = os.path.dirname(os.path.abspath(__file__))
	if not os.path.isfile(os.path.join(dirtest,FBA)):
		dirtest = os.getcwd()
	if not os.path.isfile(os.path.join(dirtest,FBA)):
		print >>sys.stderr, "Can't find", FBA
		logging.info("Can't find %s" % FBA)
		os._exit(1)

	FBA=os.path.join(dirtest,FBA)

	# try to find wine
	wine=os.path.join(dirtest,"../../Resources/usr/bin/wine")
	if not os.path.isfile(wine):
		wine="/usr/bin/wine"
	if not os.path.isfile(wine):
		wine='/usr/local/bin/wine'
	if not os.path.isfile(wine):
		# assume we are on windows
		args.insert(0, FBA)
	else:
		args.insert(0, FBA)
		args.insert(0, wine)

	try:
		logging.debug("RUNNING %s" % args)
		p = Popen(args)
	except OSError:
		print >>sys.stderr, "Can't execute", FBA
		logging.info("Can't execute %s" % FBA)
		os._exit(1)
	return p


def puncher(sock, remote_host, port):
# License: Apache License, Version 2.0
#          http://www.apache.org/licenses/
#
	my_token = str(random.random())
	logging.debug("my_token = %s" % my_token)
	remote_token = "_"

	sock.setblocking(0)
	sock.settimeout(5)

	remote_knows_our_token = False

	for i in range(10):
		r,w,x = select([sock], [sock], [], 0)

		if remote_token != "_" and remote_knows_our_token:
			logging.debug("We are done - hole was punched from both ends")
			break

		if r:
			data, addr = sock.recvfrom(1024)
			if addr[1]!=port or addr[0]!=remote_host:
				if (addr[1]!=7000):
					logging.info("Remote end uses symmetric or restricted nat. Changing from %s:%d to %s:%d." % (str(remote_host), port, str(addr[0]), addr[1]))
					port=addr[1]
					remote_host=addr[0]
			logging.debug("Recv: %r" % data)
			if remote_token == "_":
				remote_token = data.split()[0]
				logging.debug("Remote_token is now %s" % remote_token)
			if len(data.split()) == 3:
				logging.debug("Remote end signals it knows our token")
				remote_knows_our_token = True

		if w:
			data = "%s %s" % (my_token, remote_token)
			if remote_token != "_": data += " ok"
			logging.debug("Sending: %r" % data)
			sock.sendto(data, (remote_host, port))
			logging.debug("Sent %d" % i)

		time.sleep(0.5)

	logging.debug("Puncher done")

	return remote_token != "_", remote_host, port


def check_latency(ip):

	checker = os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])), "check-latency.sh")
	p1 = Popen([checker, ip, '2>&1'],stdout=PIPE)
	latency = p1.communicate()[0].strip()
	try:
		ping = int(latency)
	except ValueError:
		ping = 150
	return ping


def udp_proxy(server,args,q):

	logging.debug("UdpProxy: %s" % args)

	master_port = int(args[0].split(",")[3])
	master = (server, master_port)
	logging.debug("UdpProxy: %s" % server)
	logging.debug("UdpProxy: %d" % master_port)
	l_sockfd = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
	bindok=0
	try:
		port=7001
		l_sockfd.bind(("127.0.0.1", port))
	except socket.error:
		logging.info("Can't bind to port 7001, using system assigned port.")
		l_sockfd.sendto("", ("127.0.0.1", 7001))
		bindaddr,port=l_sockfd.getsockname()
		bindok+=1

	logging.info("Listening on 127.0.0.1:%d (udp)" % port)

	#use only the challenge id for the hole punching server
	quark = args[0].split(",")[2]
	logging.info("Quark: %s" % quark)

	try:
		sockfd = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
		sockfd.settimeout(10)
	except Exception, e:
		logging.info("Error creating udp socket. Using ports.")
		logging.info("ERROR: %s" % (repr(e)))
		fba_pid=start_fba(args)
		q.put(fba_pid)
		sockfd.sendto( "useports/"+quark, master)
		return

	# bind the socket to a port, so we can test the user's NAT type
	try:
		sockfd.bind(("0.0.0.0", 6006))
	except:
		logging.info("Can't bind to port 6006, using system assigned port.")
		bindok+=1

	if bindok>=2:
		logging.info("WARNING: Another instance of fcadefba.exe seems to be running.")

		# en debug no matar otros, para probar en local
		killFCadeFBA()
		time.sleep(2)

	try:
		logging.debug("Sending data to master")
		sockfd.sendto( quark+"/"+str(port), master )
	except Exception, e:
		logging.info("Error sending data to fightcade server. Using ports.")
		logging.info("ERROR: %s" % (repr(e)))
		fba_pid=start_fba(args)
		q.put(fba_pid)
		sockfd.sendto( "useports/"+quark, master)
		return

	try:
		data, addr = sockfd.recvfrom( len(quark)+3 )
		logging.debug("Request received from %s = %r" % (addr, data))
	except socket.timeout:
		logging.info("Timeout on master request, retrying.")
		sockfd.sendto( quark+"/"+str(port), master )
		data, addr = sockfd.recvfrom( len(quark)+3 )
	except socket.error:
		logging.info("Error receiving request from master. Using ports.")
		sockfd.sendto( "useports/"+quark, master)
		fba_pid=start_fba(args)
		q.put(fba_pid)
		return

	if data != "ok "+quark:
		print >>sys.stderr, "unable to request!"
		logging.info("Unable to request!")
		#os._exit(1)
	sockfd.sendto( "ok", master )
	logging.info("Request sent, waiting for partner in quark '%s'..." % quark)
	sockfd.settimeout(25)
	try:
		data, addr = sockfd.recvfrom( 6 )
	except socket.timeout:
		logging.info("Timeout waiting for peer's address. Using ports.")
		sockfd.sendto( "useports/"+quark, master)
		fba_pid=start_fba(args)
		q.put(fba_pid)
		return
	except socket.error:
		logging.info("Error getting peer address. Using ports.")
		sockfd.sendto( "useports/"+quark, master)
		fba_pid=start_fba(args)
		q.put(fba_pid)
		return

	target = bytes2addr(data)
	logging.debug("Connected to %s:%d" % target)

	punch_ok, r_addr, r_port, = puncher(sockfd, target[0], target[1])
	target = (r_addr, r_port)
	port = r_port
	logging.info ("Puncher result: %s" % punch_ok)

	restricted_nat=False
	if not punch_ok:
		# try to punch the hole using a new ip:port mapping that has never reached another destination
		n_sockfd = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
		try:
			logging.info("Listening on 0.0.0.0:6004/udp")
			n_sockfd.bind(("0.0.0.0", 6004))
		except socket.error:
			logging.info("Error listening on 0.0.0.0:6004/udp")
		punch_ok, r_addr, r_port, = puncher(n_sockfd, target[0], 6004)
		target = (r_addr, r_port)
		restricted_nat=True

	if not punch_ok:
		# tell the server that this quark must use ports
		logging.info("Puncher failed. Using ports.")
		sockfd.sendto( "useports/"+quark, master)

	if restricted_nat:
		sockfd.close()
		sockfd=n_sockfd

	if port!=target[1]:
		logging.info("Changing remote port from %d to %d." % (port, target[1]))

	# hook for changing the smoothing setting dynamically
	if (args[0][-1] == 'a'):
		logging.debug("Checking ping for ip: %s " % target[0])
		latency = check_latency(target[0])
		smoothing=0
		if ( latency > 130 ):
			smoothing=1
		if ( latency > 220 ):
			smoothing=2
		if ( latency > 300 ):
			smoothing=3
		if ( latency > 380 ):
			smoothing=4
		logging.info("latency: %d - Smoothing: %d " % (latency, smoothing))
		args[0] = args[0][:-1]+str(smoothing)

	fba_pid=start_fba(args)
	q.put(fba_pid)

	if not punch_ok:
		return

	# first request using blocking sockets:
	l_sockfd.settimeout(25)
	try:
		emudata, emuaddr = l_sockfd.recvfrom(16384)
		logging.debug("First request from emulator at %s = %r" % (emuaddr, emudata))
	except socket.timeout:
		logging.info("Timeout waiting for emulator")
		emuaddr = ('127.0.0.1', 6000)
		emudata=''

	if emudata:
		logging.debug("Sending data to target %s = %r" % (target, emudata))
		sockfd.sendto( emudata, target )

	try:
		peerdata, peeraddr = sockfd.recvfrom(16384)
		logging.debug("First request from peer at %s = %r" % (peeraddr, peerdata))
		logging.debug("peer %s , target %s" % (peeraddr, target))
		if peerdata and " _" in peerdata:
			peerdata, peeraddr = sockfd.recvfrom(16384)
			logging.debug("Request from peer at %s = %r" % (peeraddr, peerdata))
		if peerdata and " ok" in peerdata:
			peerdata, peeraddr = sockfd.recvfrom(16384)
			logging.debug("Request from peer at %s = %r" % (peeraddr, peerdata))
		if peerdata and " ok" not in peerdata and " _" not in peerdata:
			logging.debug("Sending data to emulator %s = %r" % (emuaddr, peerdata))
			l_sockfd.sendto( peerdata, emuaddr )
	except Exception, e:
		logging.info("Timeout waiting for peer")
		logging.info("ERROR: %s" % (repr(e)))

	logging.info("Received first request")

	# now continue the game using nonblocking:
	l_sockfd.setblocking(0)
	sockfd.setblocking(0)

	logging.info("setting nonblocking sockets")
	failed=0

	while True:
		try:
			rfds,_,_ = select( [sockfd,l_sockfd], [], [], 0.1)
			if l_sockfd in rfds:
				emudata, emuaddr = l_sockfd.recvfrom(16384)
				if emudata:
					sockfd.sendto( emudata, target )
			if sockfd in rfds:
				peerdata, peeraddr = sockfd.recvfrom(16384)
				if peerdata:
					l_sockfd.sendto( peerdata, emuaddr )
		except Exception, e:
			failed+=1
			logging.info("ERROR: %s" % (repr(e)))
			if (failed < 4):
				pass
			else:
				logging.info("Exit loop")
				sockfd.close()
				l_sockfd.close()
				os._exit(0)

def killFCadeFBA():
	if platform.system()=="Windows":
		try:
			args = ['taskkill', '/f', '/im', 'fcadefba.exe']
			Popen(args, shell=True)
			args = ['tskill', 'fcadefba', '/a']
			Popen(args, shell=True)
		except:
			logging.info("Failed to kill fcadefba")
	if platform.system()=="Darwin":
		try:
			devnull = open(os.devnull, 'w')
			args = ['pkill', '-f', 'fcadefba.exe.*quark:served']
			Popen(args, stdout=devnull, stderr=devnull)
			args = ['../../Resources/usr/bin/wineserver', '-k']
			Popen(args, stdout=devnull, stderr=devnull)
			devnull.close()
		except:
			logging.info("Failed to kill fcadefba")
	if platform.system()=="Linux":
		try:
			devnull = open(os.devnull, 'w')
			args = ['pkill', '-f', 'fcadefba.exe.*quark:served']
			Popen(args, stdout=devnull, stderr=devnull)
			args = ['wineserver', '-k']
			Popen(args, stdout=devnull, stderr=devnull)
			devnull.close()
		except:
			logging.info("Failed to kill fcadefba")



def registerUriHandler():
	from _winreg import CreateKey, SetValueEx, HKEY_CURRENT_USER, REG_SZ, CloseKey
	regKeys = []
	regKeys.append(['Software\\Classes\\fcade', '', 'Fightcade'])
	regKeys.append(['Software\\Classes\\fcade', 'URL Protocol', ""])
	regKeys.append(['Software\\Classes\\fcade\\shell', '', None])
	regKeys.append(['Software\\Classes\\fcade\\shell\\open', '',  None])

	for key,name,val in regKeys:
		registryKey = CreateKey(HKEY_CURRENT_USER, key)
		SetValueEx(registryKey, name, 0, REG_SZ, val)
		CloseKey(registryKey)

	regKeysU = []
	regKeysU.append(['Software\\Classes\\fcade\\shell\\open\\command',  '', os.path.abspath(sys.argv[0])+' "%1"'])
	for key,name,val in regKeysU:
		registryKey = CreateKey(HKEY_CURRENT_USER, key)
		SetValueEx(registryKey, name, 0, REG_SZ, val)
		CloseKey(registryKey)


def process_checker(q):
	time.sleep(15)
	fba_p=q.get()
	logging.info("fcadefba pid: %d" % int(fba_p.pid))

	while True:
		time.sleep(5)
		fba_status=fba_p.poll()
		#print "FBA STATUS:", str(fba_status)
		#logging.debug("FBA STATUS: %s" % str(fba_status))
		if fba_status!=None:
			logging.info("Killing process")
			os._exit(0)


def writeServerToDLL(server):
	logging.debug("Writing GGPO server host to DLL: %s" % server)
	try:
		dll = os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])), "ggponet.dll")
		f = open(dll, "r+b")
		f.seek(0x32152) 
		f.write(server)
		f.write('\x00')
		f.close()
	except:
		logging.info("Can't write server to ggponet.dll")


def main():

	args = sys.argv[1:]
	logging.debug("Args: %s" % args)

	params=''
	if len(args)>0:
		params=args[0]

	num_params = len(params.split('/'))

	if platform.system()=="Windows":
		registerUriHandler()

	if params.startswith('fcade://served/') and num_params >=5:
		logging.debug("Served: %s" % params)
		try:
			game=params.split('/')[3]
			quark=params.split('/')[4]
			if (num_params > 5):
				server=params.split('/')[5]
				writeServerToDLL(server)
			q = Queue.Queue()
			t = threading.Thread(target=process_checker, args=(q,))
			t.setDaemon(True)
			t.start()
			udp_proxy(server,['quark:served,'+game+','+quark, '-w'],q)
			t.join()
		except:
			pass
	elif params.startswith('fcade://stream/') and num_params >=5:
		logging.debug("Stream: %s" % params)
		try:
			game=params.split('/')[3]
			quark=params.split('/')[4]
			if (num_params > 5):
				server=params.split('/')[5]
				writeServerToDLL(server)
			start_fba(['quark:stream,'+game+','+quark, '-w'])
		except:
			pass
	elif params.startswith('fcade://server/'):
		logging.debug("Writing server to DLL: %s" % params)
		try:
			server=params.split('/')[3]
			writeServerToDLL(server)
		except:
			pass
	elif params.startswith('fcade://killemu'):
		logging.debug("Killing emulator: %s" % params)
		killFCadeFBA()
		time.sleep(2)
	else:
		start_fba(args)

if __name__ == "__main__":

	log = os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])), "fcade.log")
	errorlog = os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])), "fcade-errors.log")

	try:
		loglevel=logging.DEBUG
		#loglevel=logging.INFO
		logging.basicConfig(filename=log, filemode='w', level=loglevel, format='%(asctime)s:%(levelname)s:%(message)s')
		main()

	except:
		traceback.print_exc(file=open(errorlog,"w"))
		os._exit(1)
