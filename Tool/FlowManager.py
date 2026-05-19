import time
from collections import defaultdict, deque
import numpy as np

class FlowManager:
    def __init__(self, flow_timeout=5):
        """
        flow_timeout: time in seconds after which a flow is considered finished
        """
        self.flows = {}  # key = flow tuple, value = flow dict
        self.flow_timeout = flow_timeout  # seconds
        self.completed_flows = deque()  # store flows ready to predict

    def _flow_key(self, packet):
        """Define flow by 5-tuple"""
        return (
            packet.get('source', ''),
            packet.get('destination', ''),
            packet.get('sport', 0),
            packet.get('dport', 0),
            packet.get('protocol', 'Unknown')
        )

    def add_packet(self, packet):
        key = self._flow_key(packet)
        now = time.time()

        if key not in self.flows:
            # New flow
            self.flows[key] = {
                'packets': [],
                'timestamps': [],
                'protocol': packet.get('protocol', 'Unknown'),
                'src': packet.get('source', ''),
                'dst': packet.get('destination', ''),
                'sport': packet.get('sport', 0),
                'dport': packet.get('dport', 0),
                'flags_count': defaultdict(int)
            }

        flow = self.flows[key]
        flow['packets'].append(packet)
        flow['timestamps'].append(now)

        # Count TCP flags
        for flag in ['FIN','SYN','RST','PSH','ACK','URG','ECE','CWR']:
            if 'flags' in packet and flag in packet['flags']:
                flow['flags_count'][flag] += 1

        # Check timeout
        if now - flow['timestamps'][0] > self.flow_timeout:
            # Flow expired, move to completed
            self.completed_flows.append(flow)
            del self.flows[key]

    def get_ready_flows(self):
        """Return all completed flows and clear the queue"""
        flows = list(self.completed_flows)
        self.completed_flows.clear()
        return flows

    def get_flow_features(self, flow):
        """Compute feature vector (46 features) from a flow"""
        features = np.zeros(46)

        packets = flow['packets']
        timestamps = flow['timestamps']
        n = len(packets)

        # 0: flow_duration
        features[0] = timestamps[-1] - timestamps[0] if n > 1 else 0

        # 1: Header_Length sum (approx using packet length)
        features[1] = sum(p.get('length',0) for p in packets)

        # 2: Protocol type
        protocol_map = {'TCP':6,'UDP':17,'ICMP':1,'ARP':2}
        features[2] = protocol_map.get(flow['protocol'],0)

        # 3: Duration
        features[3] = features[0]

        # 4-6: Rate, Srate, Drate (packets/sec, src bytes/sec, dst bytes/sec)
        duration = features[0] if features[0] > 0 else 1
        total_bytes = sum(p.get('length',0) for p in packets)
        features[4] = n / duration
        features[5] = total_bytes / duration
        features[6] = total_bytes / duration

        # 7-14: Flag counts
        features[7] = flow['flags_count'].get('FIN',0)
        features[8] = flow['flags_count'].get('SYN',0)
        features[9] = flow['flags_count'].get('RST',0)
        features[10] = flow['flags_count'].get('PSH',0)
        features[11] = flow['flags_count'].get('ACK',0)
        features[12] = flow['flags_count'].get('ECE',0)
        features[13] = flow['flags_count'].get('CWR',0)
        features[14] = flow['flags_count'].get('URG',0)

        # 15-18: Counts of flags repeated in packets (simplified)
        features[15] = features[11]  # ACK count
        features[16] = features[8]   # SYN count
        features[17] = features[7]   # FIN count
        features[18] = features[9]   # RST count

        # 19-33: Protocol indicators (HTTP, HTTPS, DNS, etc.)
        proto_list = ['HTTP','HTTPS','DNS','Telnet','SMTP','SSH','IRC','TCP','UDP','DHCP','ARP','ICMP','IPv','LLC']
        for i, proto in enumerate(proto_list):
            features[19+i] = 1 if proto.lower() in flow['protocol'].lower() else 0

        # 33-39: statistical metrics: Tot sum, Min, Max, AVG, Std, Tot size, IAT
        lengths = [p.get('length',0) for p in packets]
        features[33] = sum(lengths)
        features[34] = min(lengths)
        features[35] = max(lengths)
        features[36] = np.mean(lengths)
        features[37] = np.std(lengths)
        features[38] = sum(lengths)
        # IAT = inter-arrival time mean
        if n>1:
            iat = [timestamps[i]-timestamps[i-1] for i in range(1,n)]
            features[39] = np.mean(iat)
        else:
            features[39] = 0

        # 40-45: remaining placeholders
        features[40] = n
        features[41] = np.mean(lengths)
        features[42] = 0  # Magnitue
        features[43] = 0  # Radius
        features[44] = 0  # Covariance
        features[45] = np.var(lengths)

        return features
