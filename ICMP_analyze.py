# goi icmp tu router- net un: thay doi thong bao kha voi truong hop nay
import pyshark
import sys

# ICMP analyze
ht_states={}
def in_(src_ip,dst_ip,status):
	nb= (src_ip,dst_ip)
	if nb not in ht_states or ht_states[nb]!= status:
		ht_states[nb]=status
		print(f'{src_ip} <-> {dst_ip}: {status}')

def a_icmp(pcapng_file):
	capture = pyshark.FileCapture(pcapng_file, display_filter='icmp')
	for packet in capture:
		if hasattr(packet, 'icmp'):
			if hasattr(packet, 'ip') and hasattr(packet.icmp, 'type'):
				src_ip=packet.ip.src
				dst_ip=packet.ip.dst
				icmp_type = packet.icmp.type
				icmp_code = packet.icmp.code if hasattr(packet.icmp, 'code') else None
			
				if packet.icmp.type =='0':
					in_(dst_ip,src_ip, 'connected')
				elif packet.icmp.type == '3':
					if icmp_code == '0':
						in_(src_ip,dst_ip, 'Network unreachable')
					elif icmp_code == '1':
						in_(src_ip,dst_ip, 'Host unreachable')
					elif icmp_code == '3':
						in_(src_ip,dst_ip, 'Port unreachable')
					elif icmp_code == '4':
						in_(src_ip,dst_ip, 'Fragmention Needed and Do not Fragment was set')
	capture.close()

def main():
	""" read files
	pcapng_file = 'E:\\FilePcapng\\p001-nn.pcapng'
	a_icmp(pcapng_file) 
	"""
    #read from command line arguments
	a_icmp(sys.argv[1])

if __name__ == "__main__":
	main()
