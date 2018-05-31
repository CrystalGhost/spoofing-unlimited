#!/usr/bin/python

from arp_module import redirectto

""" Ex. redirrectto(iface='eth0', server='1.2.3.4', domain='www.domain.com', port=80, enable=True) will enable 
	iptables with the current configuration. """

redirectto(iface='wlan0', server='1.2.3.4', domain='www.domain.com', port=80, enable=True)
