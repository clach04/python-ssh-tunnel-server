# TunnelServern - A SSH Tunnel implementation for and based on Paramiko.
#
# Copyright (C) 2014 Pier Angelo Vendrame <vogliadifarniente@gmail.com>
#
# This file is based on some of Paramiko examples: demo_server.py, forward.py,
# rforward.py.
# Original copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko and TunnelServer are distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this software; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

import paramiko
import logging
import socket
import select
import threading
import SocketServer

"""
This is an implementation of the tunnel handler for a SSH server based on
Paramiko.

Please note that this isn't a complete server: it won't accept any connection,
as standard Paramiko ServerInterface.
Furthermore it accepts shell requests, but it only sends a message which tells
that actually shell access is not premitted.

Another note about terminology:
* forward is Third-Party --> SSH Server --> SSH Client (-R on OpenSSH client);
* direct is SSH Client --> SSH Server --> Third-Party (-L on OpenSSH client).
You should use forward when the SSH Client wants to provide a service, whereas
you should use direct to bypass firewall when connecting to another service.
"""
class TunnelServer(paramiko.ServerInterface):
	log_name = "TunnelServer"
	no_shell = "Welcome to our system.\r\nWe're sorry, but shell access is " \
			"not permitted.\r\n"
	forwards = {}
	transport = None
	cleaner = None

	"""
	We need to save the session channel (the shell one), otherwise the session
	will be closed.
	This variable should be private, and won't be used unless our shell request
	is used.
	Please note that if you implement a shell handler, or a channel handler, the
	first channel (the session one) has to be saved somewhere, otherwise Python
	will clean it and the session will be closed.
	"""
	session_channel = None

	"""
	The consructor.
	We need the transport because we need to get channels.

	The cleaner parameter is optional, it should be an instance of Cleaner.
	If it's eighter none, or it isn't an instance of Cleaner, the class creates
	and manages its own cleaner, with its own thread.

	Note about logs: if you want to change the log name, you have to do it
	before calling the constructor, which means that you have to do it in a
	child class. Indeed the logger is created here.
	"""
	def __init__(self, transport, cleaner = None):
		# paramiko.ServerInterface hasn't a costrunctor, at the moment
		self.transport = transport
		self.logger = logging.getLogger(self.log_name)

		if isinstance(cleaner, Cleaner):
			self.cleaner = cleaner
		else:
			self.cleaner = Cleaner()
			self.cleaner.start()

	"""
	Accept sessions.
	"""
	def check_channel_request(self, kind, chanid):
		self.logger.debug("Incoming request for channel type %s.", kind)
		if kind == 'session':
			return paramiko.OPEN_SUCCEEDED
		return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

	"""
	Default shell handler: it accepts shell requests, but it sends a message
	which tells that actually shell access is not premitted.
	"""
	def check_channel_shell_request(self, channel):
		# Shell isn't our target, so log as debug
		self.logger.debug("Got shell request. Denying it.",
				extra={'username' : self.transport.get_username()})
		channel.send(self.no_shell)

		# Don't let the GC delete the channel. For further details, see above.
		self.session_channel = channel

		return True

	"""
	Pretend to accept PTY request, otherwise OpenSSH complains.
	We just don't care of parameters, so we ignore them with *args.
	"""
	def check_channel_pty_request(self, *args):
		self.logger.debug("Got the PTY request, pretending to accept it.",
				extra={'username' : self.transport.get_username()})
		return True

	"""
	Forward handler: the core of this class.
	"""
	def check_port_forward_request(self, address, port):
		username = self.transport.get_username()
		ex = {'username' : username}
		self.logger.debug("Forward request for %s:%i.", address, port,
				extra=ex)

		if not self.check_forward_address((address, port)):
			self.logger.info("Forward request for %s:%i denied to %s.", address,
					port, username, extra=ex)
			return False

		"""
		Note that the if the client requested the port, we must handle it or
		return false.
		Only if it requested 0 as port we can open a random port (actually the
		OS will tell us which port).
		If it can't be opened, we just return false.
		"""

		try:
			f = ForwardServer((address, port), Handler, self.logger,
					self.transport)
			f.start()
		except:
			# "port can't be opened" included here
			f.shutdown()
			self.logger.exception("Could not start forward.")
			return False

		ourport = f.socket.getsockname()[1]

		# Should never happen, but check it the same
		if (port != 0) and (ourport != port):
			f.shutdown()
			self.logger.warning("Port mismatch: wanted %i, got %i. " +
					"Closing forwarding.", port, ourport, extra=ex)
			return False
		else:
			self.logger.info("Forward for %s:%i opened successfully to %s.",
					address, ourport, username, extra=ex)

		self.forwards[(address, ourport)] = f

		# Paramiko requires in the cases the client doesn't need it, too
		return ourport

	"""
	Handles the closure of the port forwarding.
	"""
	def cancel_port_forward_request(self, address, port):
		username = self.transport.get_username()
		self.logger.info("Cancel port forward request on %s:%i by %s.", address,
				port, username, extra={'username' : username})

		try:
			self.forwards[(address, port)].shutdown()
			del self.forwards[(address, port)]
		except:
			self.logger.exception("Could not stop forward.")

	"""
	Direct handler, the other core part of the class.
	"""
	def check_channel_direct_tcpip_request(self, chanid, origin, destination):
		username = self.transport.get_username()
		ex = {'username' : username}

		if not self.check_direct(origin, destination):
			self.logger.debug("Rejected direct connection from %s to %s for %s.",
					origin, destination, username, extra=ex)
			return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

		self.logger.debug("Setting direct connection from %s to %s for %s.",
				origin, destination, username, extra=ex)

		try:
			f = ForwardClient(destination, self.transport, chanid, self.logger,
					self.cleaner)
			f.start()
		except:
			self.logger.exception("Could not setup forward from %s to %s.",
					origin, destination, extra=ex)
			return paramiko.OPEN_FAILED_CONNECT_FAILED

		return paramiko.OPEN_SUCCEEDED

	"""
	The implementation of the server can check if an user is authorized to
	request a forward for this address.
	By default, all users can forward ports and can bind all addresses.
	"""
	def check_forward_address(self, address):
		return True

	"""
	Like forwarding, direct tcp connection can be checked before creating it.
	"""
	def check_direct(self, origin, destination):
		return True

"""
When forwarding a port, we have to act as a server.
Therefore we use Python standard TCP Server and threads to listen for
connections to forward, which is what we do with this class.
"""
class ForwardServer(SocketServer.ThreadingTCPServer, threading.Thread):
	daemon = True # This is for Thread
	daemon_threads = daemon # This is for ThreadingTCPServer
	allow_reuse_address = True

	"""
	Initializes the forwarder.
	We actually save the parameters.
	"""
	def __init__(self, server_address, RequestHandlerClass, logger, transport,
			bind_and_activate = True):
		SocketServer.ThreadingTCPServer.__init__(self, server_address,
				RequestHandlerClass, bind_and_activate)
		threading.Thread.__init__(self)

		"""
		Save the original server address, otherwise OpenSSH will complain.
		We have some freedom on port, so make sure it is correct.
		"""
		self.bind_address = (server_address[0], self.socket.getsockname()[1])

		self.logger = logger
		self.transport = transport

	"""
	Start serving.
	This method actually have been defined to comply threading.Thread.
	"""
	def run(self):
		self.serve_forever()

	"""
	Shutdowns the forwarding and by default join the thread.
	"""
	def shutdown(self, join = True):
		SocketServer.ThreadingTCPServer.shutdown(self)
		if join:
			self.join()

	"""
	The destructor: makes sure the forwarding is closed.
	"""
	def __del__(self):
		self.shutdown()

"""
Connect a socket and a SSH channel.
"""
def tunnel(sock, chan, chunk_size = 1024):
	while True:
		r, w, x = select.select([sock, chan], [], [])

		if sock in r:
			data = sock.recv(chunk_size)
			if len(data) == 0:
				break
			chan.send(data)

		if chan in r:
			data = chan.recv(chunk_size)
			if len(data) == 0:
				break
			sock.send(data)

	chan.close()
	sock.close()

"""
Handler for Python standard SocketServer.
Note that we need our server class (i. e. ForwardServer), otherwise we don't
handle the request
"""
class Handler(SocketServer.BaseRequestHandler):
	"""
	Handles a request.
	"""
	def handle(self):
		if not isinstance(self.server, ForwardServer):
			# We only want our server!
			return False

		transport = self.server.transport
		logger = self.server.logger
		peer = self.request.getpeername()
		logger.debug("Forward request by peer %s, username: %s.", peer,
				transport.get_username())

		try:
			"""
			bind_address is a custom variable, but if somebody else used this
			handler, an exception will be raised.
			The same if the SSH client denies the permission to open the channel.
			"""
			chan = transport.open_forwarded_tcpip_channel(self.client_address,
				self.server.bind_address)
			logger.debug("Opened channel %i.", chan.get_id())
		except:
			logger.exception("Could not open the new channel.")

		try:
			logger.debug("Start tunnelling for %s.", peer)
			tunnel(self.request, chan)
			logger.debug("Tunnel for %s ended correctly.", peer)
		except:
			logger.exception("An error occurred during tunneling for %s.", peer)

"""
This class handles the direct TCP-IP connection feature of SSH.
It implements a thread to do so, however it should be closed by a cleaner.
"""
class ForwardClient(threading.Thread):
	daemon = True
	chanid = 0
	active = False
	lock = threading.Lock()
	logger = None
	cleaner = None

	def __init__(self, address, transport, chanid, logger, cleaner):
		threading.Thread.__init__(self)

		self.socket = socket.create_connection(address)
		self.transport = transport
		self.chanid = chanid
		self.logger = logger
		self.cleaner = cleaner

		cleaner.add_thread(self)

		self.logger.debug("ForwardClient for %s correctly initialized.",
				address)

	"""
	Waits for the SSH direct connection channel and start redirect.
	After that it has handled its channel, it will return and the thread will
	wait to be joined.
	"""
	def run(self):
		self.lock.acquire()
		self.active = True
		self.lock.release()

		while self.active:
			chan = self.transport.accept(10)
			if chan == None:
				continue

			self.logger.debug("Got new channel (id: %i).", chan.get_id())

			if chan.get_id() == self.chanid:
				break

		peer = self.socket.getpeername()
		self.logger.debug("Start tunneling with peer %s, username %s.",
				peer, self.transport.get_username())
		try:
			tunnel(self.socket, chan)
			self.logger.debug("Tunnel with %s ended correctly", peer)
		except:
			self.logger.exception("Tunnel exception with peer %s.", peer)

		self.lock.acquire()
		self.active = False
		self.lock.release()

		self.cleaner.set_event()

	"""
	Shutdown the thread as soon as possible.
	Note that if it is sending data, it will wait for the channel or to
	socket to be closed, and it will block the caller!
	By default this method joins the thread, too.
	"""
	def shutdown(self, join = True):
		self.logger.debug("Shutting down ForwardClient for channel %i.",
				self.chanid)

		self.lock.acquire()
		self.active = False
		self.lock.release()

		if join:
			self.join()

"""
Cleans unused threads.
"""
class Cleaner(threading.Thread):
	# The lock used to add and delete threads
	lock = threading.Lock()

	# The event to set to ask thread deletion
	event = threading.Event()

	# The threads to monitor
	threads = []

	# We run as a demon thread
	daemon = True

	"""
	Wait for an event to clean
	"""
	def run(self):
		while True:
			self.event.wait()

			for thread in self.threads:
				if not thread.active:
					thread.shutdown()

					self.lock.acquire()
					try:
						"""
						It seems that it is removed afer the next connection...
						Misteries of GC...
						"""
						self.threads.remove(thread)
					except:
						pass
					self.lock.release()

			self.event.clear()

	"""
	Add a thread to the threads list.
	"""
	def add_thread(self, thread):
		self.lock.acquire()
		self.threads.append(thread)
		self.lock.release()

	"""
	Ask for deletion by setting the event.
	"""
	def set_event(self):
		self.event.set()
