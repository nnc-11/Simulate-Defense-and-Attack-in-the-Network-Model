import pyshark
import sys
from urllib.parse import unquote 

def analyze_attack(pcap_file):
    fc = pyshark.FileCapture(pcap_file, display_filter='http')
    for packet in fc:
        if hasattr(packet, 'http'):
            if hasattr(packet.http, 'user_agent') and 'sqlmap' in packet.http.user_agent.lower():
                print(f"WARRNING: IP {packet.ip.src} is under SQLMap attack")
                print(f"HTTP User-Agent: {packet.http.user_agent}")
                print(f"Source IP: {packet.ip.src}")
                print(f"Destination IP: {packet.ip.dst}")
                print("-"*100+ "\n")
            if hasattr(packet.http, 'request_uri') and '/search.php' in packet.http.request_uri:
                search_param = packet.http.request_uri.split('?search=')[-1]
                decoded_search_param = unquote(search_param)
                if '<script>' in decoded_search_param:
                    print(f"WARRNING attack XSS: Request URI: {packet.http.request_uri}")
                    print(f"Search parameter: {decoded_search_param}")
                    print(f"Source IP: {packet.ip.src}, Destination IP: {packet.ip.dst}")
                    print("-"*100+"\n")
    fc.close()
#Main
def main():
    import sys
    if len(sys.argv) != 2:
        print("Usage: python analyze_attack.py <pcap_file>")
        return
    pcap_file = sys.argv[1]
    analyze_attack(pcap_file)
if __name__ == "__main__":
    main()
#luvim