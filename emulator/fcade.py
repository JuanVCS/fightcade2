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

emulators = {
	'fba': {
		'name': 'fcadefba',
		'exe': 'fba/fcadefba.exe',
		'parameters': '-w'
	},
	'snes9x': {
		'name': 'fcadesnes9x',
		'exe': 'snes9x/fcadesnes9x.exe',
		'parameters': ''
	}
}

active_emulator = None

rom_prefixes_to_delete = ['snes_']

def bytes2addr( bytes ):
	"""Convert a hash to an address pair."""
	if len(bytes) != 6:
		raise ValueError, "invalid bytes"
	host = socket.inet_ntoa( bytes[:4] )
	port, = struct.unpack( "H", bytes[-2:] )
	return host, port


def start_emulator(args):
	global active_emulator
	exe_file = active_emulator["exe"]

	# try to guess install directory:
	dirtest = os.path.abspath(os.path.dirname(sys.argv[0]))
	if not os.path.isfile(os.path.join(dirtest,exe_file)):
		dirtest = os.path.dirname(os.path.abspath(__file__))
	if not os.path.isfile(os.path.join(dirtest,exe_file)):
		dirtest = os.getcwd()
	if not os.path.isfile(os.path.join(dirtest,exe_file)):
		print >>sys.stderr, "Can't find", exe_file
		logging.info("Can't find %s" % exe_file)
		os._exit(1)

	file_path = os.path.join(dirtest,exe_file)

	# try to find wine
	wine=os.path.join(dirtest,"../../Resources/usr/bin/wine")
	if not os.path.isfile(wine):
		wine="/usr/bin/wine"
	if not os.path.isfile(wine):
		wine='/usr/local/bin/wine'
	if not os.path.isfile(wine):
		# assume we are on windows
		args.insert(0, file_path)
	else:
		args.insert(0, file_path)
		args.insert(0, wine)

	# remove empty arguments
	args = [a for a in args if a != '']

	try:
		logging.debug("RUNNING %s" % args)
		p = Popen(args)
	except OSError:
		print >>sys.stderr, "Can't execute", file_path
		logging.info("Can't execute %s" % file_path)
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


def udp_proxy(server,args,q):
	global active_emulator

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
		emulator_pid=start_emulator(args)
		q.put(emulator_pid)
		sockfd.sendto( "useports/"+quark, master)
		return

	# bind the socket to a port, so we can test the user's NAT type
	try:
		sockfd.bind(("0.0.0.0", 6006))
	except:
		logging.info("Can't bind to port 6006, using system assigned port.")
		bindok+=1

	if bindok>=2:
		logging.info("WARNING: Another instance of %s seems to be running." % (active_emulator["name"]))

		# en debug no matar otros, para probar en local
		killFCadeEmulator()
		time.sleep(2)

	try:
		logging.debug("Sending data to master")
		sockfd.sendto( quark+"/"+str(port), master )
	except Exception, e:
		logging.info("Error sending data to fightcade server. Using ports.")
		logging.info("ERROR: %s" % (repr(e)))
		emulator_pid=start_emulator(args)
		q.put(emulator_pid)
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
		emulator_pid=start_emulator(args)
		q.put(emulator_pid)
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
		emulator_pid=start_emulator(args)
		q.put(emulator_pid)
		return
	except socket.error:
		logging.info("Error getting peer address. Using ports.")
		sockfd.sendto( "useports/"+quark, master)
		emulator_pid=start_emulator(args)
		q.put(emulator_pid)
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

	emulator_pid=start_emulator(args)
	q.put(emulator_pid)

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

def killFCadeEmulator():
	global active_emulator

	process_name = active_emulator['exe'][active_emulator['exe'].find('/') + 1:]

	if platform.system()=="Windows":
		try:
			args = ['taskkill', '/f', '/im', process_name]
			Popen(args, shell=True)
			args = ['tskill', active_emulator['name'], '/a']
			Popen(args, shell=True)
		except:
			logging.info("Failed to kill %s" %(active_emulator['name']))
	if platform.system()=="Darwin":
		try:
			devnull = open(os.devnull, 'w')
			args = ['pkill', '-f', '%s.*quark:served' %(process_name)]
			Popen(args, stdout=devnull, stderr=devnull)
			args = ['../../Resources/usr/bin/wineserver', '-k']
			Popen(args, stdout=devnull, stderr=devnull)
			devnull.close()
		except:
			logging.info("Failed to kill %s" %(active_emulator['name']))
	if platform.system()=="Linux":
		try:
			devnull = open(os.devnull, 'w')
			args = ['pkill', '-f', '%s.*quark:served' %(process_name)]
			Popen(args, stdout=devnull, stderr=devnull)
			args = ['wineserver', '-k']
			Popen(args, stdout=devnull, stderr=devnull)
			devnull.close()
		except:
			logging.info("Failed to kill %s" %(active_emulator['name']))



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
	emulator_p=q.get()
	logging.info("emulator pid: %d" % int(emulator_p.pid))

	while True:
		time.sleep(5)
		emulator_status=emulator_p.poll()
		#print "FBA STATUS:", str(fba_status)
		#logging.debug("FBA STATUS: %s" % str(fba_status))
		if emulator_status!=None:
			logging.info("Killing process")
			os._exit(0)


def getRomFilename(name):
	for prefix in rom_prefixes_to_delete:
		if name.find(prefix) == 0:
			return name[len(prefix):]

	return name

def main():
	global active_emulator

	args = sys.argv[1:]
	logging.debug("Args: %s" % args)
	server='punch.fightcade.com'

	params=''
	if len(args)>0:
		params=args[0]

	parameters = params.split('/')
	num_params = len(parameters)

	if platform.system()=="Windows":
		registerUriHandler()

	if params.startswith('fcade://served/') and num_params >=6:
		logging.debug("Served: %s" % params)
		try:
			active_emulator=emulators[parameters[3]]
			game=getRomFilename(parameters[4])
			quark=parameters[5]
			q = Queue.Queue()
			t = threading.Thread(target=process_checker, args=(q,))
			t.setDaemon(True)
			t.start()
			time.sleep(2)
			udp_proxy(server,['quark:served,'+game+','+quark, active_emulator['parameters']],q)
			t.join()
		except:
			pass
	elif params.startswith('fcade://stream/') and num_params >=5:
		logging.debug("Stream: %s" % params)
		try:
			active_emulator=emulators[parameters[3]]
			game=getRomFilename(params.split('/')[4])
			quark=params.split('/')[5]
			start_emulator(['quark:stream,'+game+','+quark, active_emulator['parameters']])
		except:
			pass
	elif params.startswith('fcade://killemu'):
		logging.debug("Killing emulator")
		active_emulator=emulators['fba']
		killFCadeEmulator()
		active_emulator=emulators['snes9x']
		killFCadeEmulator()
		time.sleep(2)
	elif params.startswith('fcade://play/'):
		logging.debug("Playing: %s" % params)
		try:
			active_emulator=emulators[parameters[3]]
			game=getRomFilename(parameters[4])
			start_emulator([game, active_emulator['parameters']])
		except:
			pass
	elif params.startswith('fcade://direct/'):
		# fcade://direct/<emu>/<game>/<ip>/<side>
		logging.debug("Direct: %s" % params)
		try:
			active_emulator=emulators[parameters[3]]
			game=getRomFilename(params.split('/')[4])
			ip=params.split('/')[5]
			side=params.split('/')[6]
			if (side==0):
				port1=6000
				port2=6001
			else:
				port1=6001
				port2=6000
			start_emulator(['quark:direct,'+game+','+str(port1)+','+str(ip)+','+str(port2)+','+str(side), active_emulator['parameters']])
		except:
			pass
	else:
		active_emulator=emulators['fba']
		start_emulator(args)

if __name__ == "__main__":

	log = os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])), "fcade.log")
	errorlog = os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])), "fcade-errors.log")
	try:
		#loglevel=logging.DEBUG
		loglevel=logging.INFO
		logging.basicConfig(filename=log, filemode='w', level=loglevel, format='%(asctime)s:%(levelname)s:%(message)s')
		main()
	except:
		traceback.print_exc(file=open(errorlog,"w"))
		os._exit(1)
