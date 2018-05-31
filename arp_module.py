#!/usr/bin/python
import struct,copy,socket,sys
from scapy.all import *
import nmap

"""This module setups iptables to redirect traffic through a server.
   Ex. redirrectto(iface='eth0', server='1.2.3.4', domain='www.domain.com', port=80, enable=True) will enable iptables with the current configuration.
   """


class Filter():
	def __init__(self, **fields):
		v = ['iface','server','port','domain', 'enable']
		for i, l in enumerate(v):
        		pass
              		p = i + 1
		for count in range(p):
			x = v[count]

		iface = v[0]
		address = v[1]
		port = v[2]
		domain = v[3]
		enable = v[4]
		values = fields.values()
		keys = fields.keys()
		# domain 0, enable 1, server 2, iface 3, port 4
		if  iface not in keys:
			sys.exit('[!]Error: Interface is required')
		if enable not in keys:
			sys.exit('[!]Error: Enable is required')
		value_in_key(values, keys, address, domain, port)


# from scapy/fields.py module
class Field():
    def __init__(self, name, default, **fields):
        self.name = name
	self.default = default

class IfaceField(Field):
	def __init__(self, name, default):
        	Field.__init__(self, name, default)

class ServerField(Field):
        def __init__(self, name, default):
                Field.__init__(self, name, default)

class DomainField(Field):
        def __init__(self, name, default):
                Field.__init__(self, name, default)

class PortField(Field):
	def __init__(self, name, default):
		Field.__init__(self, name, default)

class EnableField(Field):
        def __init__(self, name, default):
                Field.__init__(self, name, default)
# From scapy/
class redirectto(Filter):
    local = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]
    name = "redirectto"
    fields_desc = [ 	IfaceField('iface', 'eth0'),
			ServerField('server', local),
                 	DomainField('domain', 'domain.com:80'),
		 	PortField('port', '80'),
			EnableField('enable', False)]

# Used to check address resolutions, but it's not stealthy
# There are other methods of doing this which are more stealthy.
def check_socket(values):
	print '[*]AddrCheck: Checking Addresses'
	x = values
	addr = [x[0], x[2], x[4]]
	nm=nmap.PortScanner()
	for i in range(len(addr)):
	        nm.scan(hosts=addr[i], arguments='-sn')
		time.sleep(1)
		x = nm.scanstats()
		if int(x.values()[0]) == 0:
			sys.exit('[!]AddrError: %s is not in Service' % addr[i])
	print '[*]Success: Addresses are in Service'

def value_in_key(values, keys, address, domain, port):
	global answer
	global enable

	if address not in keys:	#no server option
		print '[*]Success: Using_Local_IP'
		server = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]
                if domain not in keys and port in keys: # no domain option, but using port option
                        print '[*]Success: Spoofing_All_Domains'
                        answer = False
                        enable = values[0]
                        iface = values[1]
                        port = values[2]

                if domain not in keys and port not in keys:
                        print '[*]Success: Spoofing_All_Domains'
                        answer = False
			enable = values[0]
			iface = values[1]
			port = '80'

                if domain in keys and port in keys:
                        print '[*]Success: Spoofing_Domain:[%s]' % domain
                        answer = True
                        domain = values[0]
                        enable = values[1]
                        port = values[2]
			iface = values[3]

                if domain in keys and port not in keys:
                        print '[*]Success: Spoofing_Domain:[%s]' % domain
			answer = True
			domain = values[0]
			enable = values[1]
			iface = values[2]
			port = '80'

	elif address in keys:	# using server option
		print '[*]Success: Using_Server_IP'
		if domain not in keys and port in keys:
		       	print '[*]Success: Spoofing_All_Domains'
			answer = False
			enable = values[0]
			iface = values[1]
			port = values[2]
			server = values[3]

		if domain not in keys and port not in keys:
		       	print '[*]Success: Spoofing_All_Domains'
	                answer = False
			enable = values[0]
			iface = values[1]
			server = values[2]
			port = '80'

		if domain in keys and port in keys:
			print '[*]Success: Spoofing_Domain:[%s]' % domain
			answer = True
			domain = values[0]
			enable = values[1]
			port = values[2]
			server = values[3]
			iface = values[4]

		if domain in keys and port not in keys:
			print '[*]Success: Spoofing_Domain:[%s]' % domain
			answer = True
			domain = values[0]
			enable = values[1]
			iface = values[2]
			server = values[3]
			ports = '80'

def address_match(iface, server, domain, port):
	a = [server, domain]
	if ':' in domain:
		domain_addr, domain_port = a[1].split(':')
		domain = domain_addr

	if ':' in server:
		server_addr, server_port = a[0].split(':')
		server = server_addr

	enable_setting(iface, server, domain, domain_port, server_port, port)

def enable_setting(iface, server, domain, domain_port, server_port, port):
	if enable is True:
		print '[*]Apache_Server: Started'
		print '[*]IP_Forwarding: Enabled'
		print '[*]IP_Tables: Safely_Added'
		table_enable(iface, server, domain, domain_port, server_port, port)

	if enable is False:
		print '[*]Apache_Server: Stopped'
                print '[*]IP_Forwarding: Disabled'
		print '[*]IP_Tables: Safely_Restored'
		table_disable(iface, server, domain, domain_port, server_port, port)

def table_disable(iface, server, domain, domain_port, server_port, port):
	os.system('sysctl -q net.ipv4.ip_forward=0')
	os.system('systemctl -q stop apache2')

	# ALL IPTABLES
	if answer is True:
                os.system('iptables -t filter -D FORWARD -p tcp --dport %s --dst %s --in-interface %s -j ACCEPT' % (server_port, server, iface))
                os.system('iptables -t nat -D PREROUTING -p tcp --dport %s --dst %s -j DNAT --to-destination %s' % (domain_port, domain, server))
                os.system('iptables -t nat -D POSTROUTING -p tcp --sport %s --out-interface %s -j MASQUERADE' % (server_port, iface))

	# ELF IPTABLES
	elif answer is False:
		os.system('iptables -t filter -D FORWARD -p tcp --dport %s --dst %s --in-interface %s -j ACCEPT' % (server_port, server, iface))
		os.system('iptables -t nat -D PREROUTING -p tcp --dport %s -j DNAT --to-destination %s' % (port, server))
        	os.system('iptables -t nat -D POSTROUTING -p tcp --sport %s --out-interface %s -j MASQUERADE' % (port, iface))


def table_enable(iface, server, domain, domain_port, server_port, port):
        os.system('sysctl -q net.ipv4.ip_forward=1')
        os.system('systemctl -q start apache2')

	if address not in keys: #no server option
                print '[*]Success: Using_Local_IP'
                server = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]
                if domain not in keys and port in keys: # no domain option, but using port option
                        print '[*]Success: Spoofing_All_Domains'
                        answer = False
                        enable = values[0]
                        iface = values[1]
                        port = values[2]

		if domain not in keys and port not in keys:
                        print '[*]Success: Spoofing_All_Domains'
                        answer = False
                        enable = values[0]
                        iface = values[1]
                        port = '80'


	elif address in keys:   # using server option
                print '[*]Success: Using_Server_IP'
                if domain not in keys and port in keys:
                        print '[*]Success: Spoofing_All_Domains'
                        answer = False
                        enable = values[0]
                        iface = values[1]
                        port = values[2]
                        server = values[3]

                if domain not in keys and port not in keys:
                        print '[*]Success: Spoofing_All_Domains'
                        answer = False
                        enable = values[0]
                        iface = values[1]
                        server = values[2]
                        port = '80'

	# ELF IPTABLES
	if answer is False:
		os.system('iptables -t filter -A FORWARD -p tcp --dport %s --dst %s --in-interface %s -j ACCEPT' % (server_port, server, iface))
		os.system('iptables -t nat -A PREROUTING -p tcp --dport %s -j DNAT --to-destination %s' % (port, server))
		os.system('iptables -t nat -A POSTROUTING -p tcp --sport %s --out-interface %s -j MASQUERADE' % (port, iface))


	# ALL IPTABLES
        if answer is True:
        	os.system('iptables -t filter -A FORWARD -p tcp --dport %s --dst %s --in-interface %s -j ACCEPT' % (server_port, server, iface))
        	os.system('iptables -t nat -A PREROUTING -p tcp --dport %s --dst %s -j DNAT --to-destination %s' % (port, domain, server))
        	os.system('iptables -t nat -A POSTROUTING -p tcp --sport %s --out-interface %s -j MASQUERADE' % (port, iface))
