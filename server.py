#!/usr/bin/env python

# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
# Copyright (C) 2014 Pier Angelo Vendrame <vogliadifarniente@gmail.com>
#
# This file is based on Paramiko demo_server.py
#
# This is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

import base64
from binascii import hexlify
import traceback
import SocketServer
import logging
import sys

import paramiko
from paramiko.py3compat import b, u, decodebytes

from tunnelserver import TunnelServer, Cleaner

# setup logging
paramiko.util.log_to_file('server.log')
logging.getLogger("TunnelServer").setLevel(logging.INFO)
h = logging.StreamHandler(sys.stdout)
h.setLevel(logging.INFO)
logging.getLogger("TunnelServer").addHandler(h)

host_key = paramiko.RSAKey(filename='test_rsa.key')
#host_key = paramiko.DSSKey(filename='test_dss.key')

print('Server public key: ' + u(hexlify(host_key.get_fingerprint())))

class Server(TunnelServer):
	# Only accepts foo as global password
	def check_auth_password(self, username, password):
		if password == 'foo':
			return paramiko.AUTH_SUCCESSFUL
		return paramiko.AUTH_FAILED

	# Always accepts login with public key
	def check_auth_publickey(self, username, key):
		print('Auth attempt with key: ' + u(hexlify(key.get_fingerprint())))
		return paramiko.AUTH_SUCCESSFUL

	# We want either public key or password login
	def get_allowed_auths(self, username):
		return 'password,publickey'

class SSHServer(SocketServer.TCPServer):
	cleaner = None

	def __init__(self, address = ('localhost', 2200)):
		self.cleaner = Cleaner()
		self.cleaner.start()
		SocketServer.TCPServer.__init__(self, address, SSHHandler)

	"""
	We don't want TCPServer to close the socket for two reasons:
	1. we create a thread which needs the socket;
	2. Paramiko Transport will close it automatically.
	Therefore we have to override default behaviour.
	"""
	def shutdown_request(self, request):
		pass

class SSHHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		try:
			cleaner = server.cleaner
		except:
			cleaner = None

		try:
			t = paramiko.Transport(self.request)
			t.add_server_key(host_key)
			t.set_keepalive(60)
			server = Server(t, cleaner)

			try:
				t.start_server(server=server)
			except paramiko.SSHException:
				print('*** SSH negotiation failed.')

		except Exception as e:
			print('*** Caught exception: ' + str(e.__class__) + ': ' + str(e))
			traceback.print_exc()

			try:
				t.close()
			except:
				pass

s = SSHServer()
s.serve_forever()
