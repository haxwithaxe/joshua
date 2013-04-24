import argparse
import random
import re
import readline
import sys
# actor model http://pypi.python.org/pypi/Pykka
import pykka
# written in C http://pypi.python.org/pypi/netifaces
import netifaces
from scapy.all import *

SEND_ONLY_MODE = 'send'
SEND_THEN_LISTEN_MODE = 'both'
LISTEN_ONLY_MODE = 'listen'
BAD_IPV4_ADDR_REGEXS = ['0\.0\.0\.0','255\.[0-9]+\.[0-9]+\.[0-9]+','127\.[0-9]+\.[0-9]+\.[0-9]+']
argp = argparse.ArgumentParser()

DEBUG=True
CMD_PROMPT='>>> '
Tx_PROMPT = 'message>'
Tx_HOST_PROMPT = 'dest host [random IPv4]>'
Tx_PORT_PROMPT = 'dest port [random port]>'
Rx_PROMPT = '>>'
Rx_EMPTY_PROMPT = '<empty>>>'

class FullStop(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

def init_argp():
	argp.add_argument('-d', '--dest', dest='dest_host', default=None)
	argp.add_argument('-p', '--dport', dest='dest_port', default=None)
	argp.add_argument('-s', '--src', dest='src_host', default=None)
	argp.add_argument('-sp', '--sport', dest='src_port', default=None)
	argp.add_argument('-i', '--interactive', dest='interactive', action='store_true')
	argp.add_argument('-l', '--listen-only', dest='listen_only', action='store_true')
	argp.add_argument('message', metavar='M', nargs='*', default=None)

def handle_args(args=[]):
	vals = argp.parse_args(args)
	#print(vals)
	if vals.listen_only:
		mode = LISTEN_ONLY_MODE
	elif vals.interactive:
		mode = SEND_THEN_LISTEN_MODE
	else:
		mode = SEND_ONLY_MODE

	if vals.interactive:
		InteractiveCLI(
			mode=mode,
			src={'host':vals.src_host, 'port':vals.src_port},
			dest={'host':vals.dest_host, 'port':vals.dest_port},
			msg=' '.join(vals.message))
	else:
		NonInteractiveCLI(
				mode=mode,
				src={'host':vals.src_host, 'port':vals.src_port},
				dest={'host':vals.dest_host, 'port':vals.dest_port},
				msg=' '.join(vals.message))

## Begin Actors ##
class Sender(pykka.ThreadingActor):
	def __init__(self, master=None, dest={'host':None, 'port':None}, src={'host':None, 'port':None}, msg=None):
		super(Sender, self).__init__()
		self.master = master
		self.dest = dest
		self.src = src
		self.msg = msg
		print('Sender', self.dest, self.src, self.msg)

	def on_receive(self, message):
		reply_to = None
		if 'command' in message:
			if message['command'] == STOP:
				self.stop()
		if 'reply_to' in message:
			 reply_to = message['reply_to']
		if 'send_to' in message and 'payload' in message:
			msg = self.pad(message['payload'])
			dest = message['send_to']
			if 'send_from' in message:
				src = message['send_from']
			else:
				src = {'host': None, 'port':None}
			self.send_msg(dest=dest, src=src, msg=msg)
			if reply_to: reply_to.tell({'type': 'sys', 'reply': [dest, src, msg]})

	def debug(self, *msg):
		msg = ' '.join([repr(m) for m in msg ])
		if self.master:
			self.master.tell({'debug': msg})
		else:
			print(msg)

	def matches(self, rel, string):
		for r in rel:
			if re.match(r, string):
				return True
		return False

	def is_ok_ip(self, addr):
		if addr.replace('.','\\.') in [ x.replace('\\.','.') for x in BAD_IPV4_ADDR_REGEXS ] or self.matches(BAD_IPV4_ADDR_REGEXS, addr):
			return False
		return True

	def get_rand_ip(self):
		rand_addr = '%d.%d.%d.%d' % (random.choice(range(0,256)),random.choice(range(0,256)),random.choice(range(0,256)),random.choice(range(0,256)))
		if self.is_ok_ip(rand_addr):
			return rand_addr
		else:
			return self.get_rand_ip()

	def get_rand_port(self):
		return random.choice(range(65335))

	def pad(self, string):
		return '\0\0\0'+string+'\0\0\0'

	def send_msg(self):
		self.dest['port'] = self.dest['port'] or self.get_rand_port()
		self.dest['host'] = self.dest['host'] or self.get_rand_ip()
		if src['port']:
			udp = UDP(dest_port=self.dest['port'],src_port=self.src['port'])
		else:
			udp = UDP(dest_port=self.dest['port'])
		if payload:
			udp.add_payload(self.msg)
		if src['host']:
			ip = IP(dst=self.dest['host'], src=self.src['host'])
		else:
			ip = IP(dst=self.dest['host'])
		send(ip/udp, verbose=0)
		if payload: udp.remove_payload()

class Localhost(object):
	def __init__(self):
		self.interfaces = []
		self.ip_addrs = []
		self.hostnames = []
		self.get_interfaces()
		self.get_ip_addrs()
		self.get_hostnames()

	def get_interfaces(self):
		self.interfaces = netifaces.interfaces()
	
	def get_ip_addrs(self):
		for i in [netifaces.ifaddresses(x) for x in self.interfaces]:
			if netifaces.AF_INET in i:
				self.ip_addrs += [x['addr'] for x in i[netifaces.AF_INET]]
			if netifaces.AF_INET6 in i:
				print('found ipv6 addr: %s' % str([x['addr'].split('%')[0] for x in i[netifaces.AF_INET6]]))
	
	def get_hostnames(self):
		pass

class Listener(pykka.ThreadingActor):
	def __init__(self, **kwargs):
		super(Listener, self).__init__()
		self.localhost = Localhost()
		print('Listener', kwargs)

	def on_receive(self, message):
		if 'command' in message:
			if message['command'] == STOP:
				self.stop()

	def run(self):
		while True:
			try:
				self.sniff_reply()
			except Exception as e:
				if type(e) == FullStop:
					return None
				self.debug('INFO',e)

	def sniff_reply(self):
		filter_str = 'udp'
		pkt = sniff(filter_str)
		reply_src = pkt.sprintf('%IP.src')
		if reply_src not in self.localhost.ip_addrs:
			reply = pkt.sprintf('%UDP.payload')
			if reply and len(reply) > 0:
				self.master.tell({'lsrc':reply_src,'lmsg':reply})

	def debug(self, *msg):
		msg = ' '.join([repr(m) for m in msg])
		if self.master:
			self.master.tell({'debug':msg})
		else:
			print(msg)

class NonInteractiveCLI(pykka.ThreadingActor):
	def __init__(self, mode=SEND_ONLY_MODE, dest={'host':None, 'port':None}, src={'host':None, 'port':None}, msg=None):
		super(NonInteractiveCLI, self).__init__()
		print(mode, dest, src, msg)
		self.mode = mode
		if self.mode in (SEND_ONLY_MODE, SEND_THEN_LISTEN_MODE):
			self.sender = Sender(master=self.actor_ref, dest=dest, src=src, msg=msg).start()
		elif self.mode in (LISTEN_ONLY_MODE, SEND_THEN_LISTEN_MODE):
			self.listener = Listener(self.actor_ref).start()
		else:
			print('no such mode for noninteractive mode.')

	def on_receive(self, message):
		if 'debug' in message:
			self.debug(message['debug'])
		if 'lsrc' in message and 'lmsg' in message:
			self.got(msg=message['lmsg'], src=message['lsrc'])
	
	def got(msg=None, src='unkown'):
		if msg and src:
			print('%(src)s %(prompt)s %(msg)s' % {'msg':msg, 'src': src, 'prompt': Rx_PROMPT})
		elif not msg and src:
			print('%(src)s %(prompt)s' % {'src': src, 'prompt': Rx_EMPTY_PROMPT})

	def stop(self):
		if self.mode in (SEND_ONLY_MODE, SEND_THEN_LISTEN_MODE):
			self.sender.stop()
		elif self.mode in (LISTEN_ONLY_MODE, SEND_THEN_LISTEN_MODE):
			self.listener.stop()
		super(NonInteractiveCLI, self).stop()

	def debug(self, *msg):
		if DEBUG: print(''.join([repr(m) for m in msg]))

class InteractiveCLI(pykka.ThreadingActor):
	def __init__(self, mode=None, dest={'host':None, 'port':None}, src={'host':None, 'port':None}, msg=None):
		print(mode, dest, src, msg)
		super(InteractiveCLI, self).__init__()
		self.sender = Sender(self.actor_ref).start()
		self.listener = Listener(self.actor_ref).start()
		self.mode = mode
		self.dest = dest
		self.src = src
		self.msg = msg
	
	def on_receive(self, message):
		if 'debug' in message:
			self.debug(message['debug'])

	def run(self):
		while keep_running:
			self.cli_script()

	def broadcast(self, msg):
		self.sender.tell(msg)
		self.listener.tell(msg)

	def all_stop(self):
		self.broadcast({'command':STOP})
		self.sender.stop()
		self.listener.stop()

	def cli_script(self):
		if not self.am_set():
			self.ask_host()
			self.ask_port()
		self.ask_msg()
			
	def forget(self):
		self.dest = {'host': None, 'port': None}
		self.src = {'host': None, 'port':None}
		self.msg = None

	def am_set(self):
		if dest['host'] and dest['port']: #src['host'] and src['port']:
			return True
		return False

	def ask_dest_port(self):
		def recurse():
			port_str=raw_input('%s ' % Tx_PORT_PROMPT)
			if port_str:
				try:
					return int(port_str, 10)
				except:
					self.debug('invalid port number %s.' % port_str)
					return recurse()
			return None
		port = recurse() or (self.dest['port'] or self.get_rand_port())
		self.dest['port'] = port

	def ask_dest_host(self):
		host = raw_input('%s ' % Tx_HOST_PROMPT)
		if host:
			self.dest['host'] = host

	def ask_msg(self):
		payload = raw_input('%s ' % Tx_PROMPT) or self.msg
		if payload and payload != self.msg and not self.is_cmd(payload):
			self.msg = payload

	def is_cmd(self, msg=None):
		if not msg: return False
		self.debug('is_cmd payload',msg)
		cmd = msg.lower().strip().split()[0]
		if cmd in ('/exit','.exit','!exit'):
			self.all_stop()
		elif cmd in ('/back','/up'):
			self.forget()
		else:
			return False
		return True

if __name__ == '__main__':
	init_argp()
	args = [x for x in sys.argv] # copy the list
	junk = args.pop(0) # remove script name
	handle_args(args)
