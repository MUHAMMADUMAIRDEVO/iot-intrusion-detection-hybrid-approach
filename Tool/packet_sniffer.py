import socket
import struct
import time
import threading
from datetime import datetime
from collections import deque, defaultdict
import pandas as pd
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
import warnings
warnings.filterwarnings("ignore")

class PacketSniffer:
    def __init__(self, interface=None):
        self.interface = interface
        self.is_sniffing = False
        self.sniffer_thread = None
        self.packets = deque(maxlen=10000)  # Keep last 10,000 packets
        self.stats = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'sources': defaultdict(int),
            'destinations': defaultdict(int),
            'start_time': None
        }
        self.packet_callbacks = []
        
    def add_packet_callback(self, callback):
        """Add callback function to be called when new packet arrives"""
        self.packet_callbacks.append(callback)
    
    def remove_packet_callback(self, callback):
        """Remove callback function"""
        if callback in self.packet_callbacks:
            self.packet_callbacks.remove(callback)
    
    def packet_handler(self, packet):
        """Process each captured packet"""
        if not self.is_sniffing:
            return
            
        packet_info = self.extract_packet_info(packet)
        if packet_info:
            self.packets.append(packet_info)
            self.stats['total_packets'] += 1
            
            # Update statistics
            self.stats['protocols'][packet_info['protocol']] += 1
            self.stats['sources'][packet_info['source']] += 1
            self.stats['destinations'][packet_info['destination']] += 1
            
            # Notify all callbacks (for GUI updates)
            for callback in self.packet_callbacks:
                try:
                    callback(packet_info)
                except Exception as e:
                    print(f"Callback error: {e}")
    
    def extract_packet_info(self, packet):
        """Extract relevant information from packet"""
        try:
            packet_info = {
                'timestamp': datetime.now(),
                'time_str': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'source': 'Unknown',
                'destination': 'Unknown',
                'protocol': 'Unknown',
                'length': len(packet),
                'info': '',
                'hex_data': '',
                'raw_packet': packet
            }
            
            # Ethernet layer
            if Ether in packet:
                packet_info['src_mac'] = packet[Ether].src
                packet_info['dst_mac'] = packet[Ether].dst
            
            # IP layer
            if IP in packet:
                packet_info['source'] = packet[IP].src
                packet_info['destination'] = packet[IP].dst
                packet_info['protocol'] = self.get_protocol_name(packet[IP].proto)
                
                # TCP
                if TCP in packet:
                    tcp = packet[TCP]
                    packet_info['info'] = f"TCP {packet_info['source']}:{tcp.sport} -> {packet_info['destination']}:{tcp.dport} "
                    packet_info['info'] += f"Flags: {self.get_tcp_flags(tcp.flags)} Seq: {tcp.seq} Ack: {tcp.ack}"
                    packet_info['sport'] = tcp.sport
                    packet_info['dport'] = tcp.dport
                    
                # UDP
                elif UDP in packet:
                    udp = packet[UDP]
                    packet_info['info'] = f"UDP {packet_info['source']}:{udp.sport} -> {packet_info['destination']}:{udp.dport}"
                    packet_info['sport'] = udp.sport
                    packet_info['dport'] = udp.dport
                    
                # ICMP
                elif ICMP in packet:
                    icmp = packet[ICMP]
                    packet_info['info'] = f"ICMP {packet_info['source']} -> {packet_info['destination']} Type: {icmp.type}"
                    
            # ARP packets
            elif ARP in packet:
                arp = packet[ARP]
                packet_info['source'] = arp.psrc
                packet_info['destination'] = arp.pdst
                packet_info['protocol'] = 'ARP'
                packet_info['info'] = f"ARP {arp.op} {arp.psrc} -> {arp.pdst}"
            
            # Get hex data (first 64 bytes)
            packet_info['hex_data'] = self.get_hex_dump(packet)
            
            return packet_info
            
        except Exception as e:
            print(f"Error extracting packet info: {e}")
            return None
    
    def get_protocol_name(self, proto_num):
        """Convert protocol number to name"""
        protocol_names = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            2: 'IGMP',
            41: 'IPv6',
            89: 'OSPF'
        }
        return protocol_names.get(proto_num, f'Proto_{proto_num}')
    
    def get_tcp_flags(self, flags):
        """Convert TCP flags to string representation"""
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        return '/'.join(flag_names) if flag_names else 'None'
    
    def get_hex_dump(self, packet, max_bytes=64):
        """Create hex dump of packet data"""
        try:
            raw_data = bytes(packet)
            hex_str = ' '.join(f'{b:02x}' for b in raw_data[:max_bytes])
            if len(raw_data) > max_bytes:
                hex_str += ' ...'
            return hex_str
        except:
            return ''
    
    def start_sniffing(self, filter_str=None, count=0):
        """Start packet sniffing"""
        if self.is_sniffing:
            return False
            
        self.is_sniffing = True
        self.stats['start_time'] = datetime.now()
        
        def sniff_thread():
            try:
                sniff(
                    prn=self.packet_handler,
                    filter=filter_str,
                    count=count,
                    iface=self.interface,
                    store=0
                )
            except Exception as e:
                print(f"Sniffing error: {e}")
            finally:
                self.is_sniffing = False
        
        self.sniffer_thread = threading.Thread(target=sniff_thread, daemon=True)
        self.sniffer_thread.start()
        return True
    
    def stop_sniffing(self):
        """Stop packet sniffing"""
        self.is_sniffing = False
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            # Scapy doesn't have a clean way to stop sniffing, so we use a flag
            pass
    
    def get_recent_packets(self, count=100):
        """Get most recent packets"""
        return list(self.packets)[-count:]
    
    def get_statistics(self):
        """Get current statistics"""
        stats = self.stats.copy()
        if stats['start_time']:
            stats['duration'] = datetime.now() - stats['start_time']
        return stats
    
    def clear_packets(self):
        """Clear captured packets"""
        self.packets.clear()
        self.stats = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'sources': defaultdict(int),
            'destinations': defaultdict(int),
            'start_time': self.stats['start_time']
        }
    
    def save_packets_to_file(self, filename, format='csv'):
        """Save captured packets to file"""
        try:
            if format.lower() == 'csv':
                df = pd.DataFrame(self.packets)
                # Remove raw_packet column as it's not serializable
                if 'raw_packet' in df.columns:
                    df = df.drop('raw_packet', axis=1)
                df.to_csv(filename, index=False)
            elif format.lower() == 'pcap':
                wrpcap(filename, [p['raw_packet'] for p in self.packets if 'raw_packet' in p])
            return True
        except Exception as e:
            print(f"Error saving packets: {e}")
            return False

# Utility function to get available network interfaces
def get_network_interfaces():
    """Get list of available network interfaces"""
    try:
        from scapy.arch.windows import get_windows_if_list
        interfaces = get_windows_if_list()
        return [iface['name'] for iface in interfaces]
    except:
        try:
            return sorted(iface for iface in get_if_list() if iface != 'lo')
        except:
            return ['Ethernet', 'Wi-Fi']  # Fallback

if __name__ == "__main__":
    # Test the sniffer
    sniffer = PacketSniffer()
    print("Available interfaces:", get_network_interfaces())
    
    def print_packet(packet):
        print(f"{packet['time_str']} {packet['protocol']} {packet['source']} -> {packet['destination']} {packet['info']}")
    
    sniffer.add_packet_callback(print_packet)
    print("Starting sniffer for 10 packets...")
    sniffer.start_sniffing(count=10)
    
    # Wait for completion
    time.sleep(15)
    sniffer.stop_sniffing()