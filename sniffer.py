from scapy.all import sniff, TCP, IP, ICMP, conf
from config import Database
from ml_engine import MLEngine
import datetime
import collections

# Database and ML Initialization
db = Database(db_name="mnids")
ml = MLEngine()

# Thresholds for detection
SYN_SCAN_THRESHOLD = 10
TIME_WINDOW = 10 # seconds

# Tracking flows for behaviors (duration, packet count)
# Key: (src, sport, dst, dport, proto)
active_flows = {}
syn_tracker = collections.defaultdict(list)

def get_tcp_flags(packet):
    if packet.haslayer(TCP):
        return str(packet[TCP].flags)
    return "N/A"

def log_alert(source_ip, dest_ip, protocol, alert_type, description, severity="Medium", packet_size=0, tcp_flags="N/A"):
    try:
        # Use ML to predict attack type and confidence
        # For simplicity, we use the rule-based alert_type as a hint or let ML override
        duration = 0.5 # Default small duration for single packet alerts
        ml_prediction, confidence = ml.predict(packet_size, protocol, tcp_flags, duration)
        
        query = """INSERT INTO alerts 
                   (source_ip, destination_ip, protocol, packet_size, tcp_flags, alert_type, ml_prediction, confidence_score, description, severity) 
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        params = (source_ip, dest_ip, protocol, int(packet_size), tcp_flags, alert_type, ml_prediction, confidence, description, severity)
        db.single_insert(query, params)
        print(f"🚨 [ML ALERT] {ml_prediction} ({int(confidence*100)}%) from {source_ip}")
    except Exception as e:
        print(f"Error logging alert: {e}")

def update_flow(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = packet.sprintf("%IP.proto%")
    packet_size = len(packet)
    
    sport = packet.sport if hasattr(packet, 'sport') else 0
    dport = packet.dport if hasattr(packet, 'dport') else 0
    tcp_flags = get_tcp_flags(packet)

    flow_key = (src_ip, sport, dst_ip, dport, proto)
    now = datetime.datetime.now()

    if flow_key not in active_flows:
        # New flow
        active_flows[flow_key] = {
            'start_time': now,
            'packet_count': 1,
            'byte_count': packet_size,
            'flags': {tcp_flags} if tcp_flags != "N/A" else set()
        }
    else:
        # Existing flow
        flow = active_flows[flow_key]
        flow['packet_count'] += 1
        flow['byte_count'] += packet_size
        if tcp_flags != "N/A":
            flow['flags'].add(tcp_flags)
        
        # Calculate duration
        duration = (now - flow['start_time']).total_seconds()
        
        # Periodic update to DB (every 10 packets to avoid heavy DB load)
        if flow['packet_count'] % 10 == 0:
            try:
                query = """INSERT INTO flow_logs 
                           (source_ip, source_port, destination_ip, destination_port, protocol, packet_count, byte_count, tcp_flags, duration_sec) 
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                           ON DUPLICATE KEY UPDATE 
                           packet_count=VALUES(packet_count), byte_count=VALUES(byte_count), duration_sec=VALUES(duration_sec)"""
                # Note: MySQL ON DUPLICATE KEY UPDATE requires a unique key. 
                # For simplicity in this mini-version, we'll just INSERT a new log entry or update the alert logic.
                # Let's just INSERT to keep track of history.
                query_insert = "INSERT INTO flow_logs (source_ip, source_port, destination_ip, destination_port, protocol, packet_count, byte_count, tcp_flags, duration_sec) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
                db.single_insert(query_insert, (src_ip, sport, dst_ip, dport, proto, flow['packet_count'], flow['byte_count'], ",".join(flow['flags']), duration))
            except Exception as e:
                pass

    return packet_size, tcp_flags

def detect_attacks(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet.sprintf("%IP.proto%")
        
        packet_size, tcp_flags = update_flow(packet)
        
        # 1. ICMP Detection
        if packet.haslayer(ICMP):
            log_alert(src_ip, dst_ip, "ICMP", "ICMP Packet Detected", f"ICMP packet from {src_ip}", "Low", packet_size, tcp_flags)

        # 2. SYN Scan Detection
        if packet.haslayer(TCP):
            if packet[TCP].flags == "S":  
                current_time = datetime.datetime.now()
                syn_tracker[src_ip].append(current_time)
                syn_tracker[src_ip] = [t for t in syn_tracker[src_ip] if (current_time - t).total_seconds() < TIME_WINDOW]
                
                if len(syn_tracker[src_ip]) > SYN_SCAN_THRESHOLD:
                    log_alert(src_ip, dst_ip, "TCP", "Possible SYN Scan", f"Detected {len(syn_tracker[src_ip])} SYN packets", "High", packet_size, tcp_flags)
                    syn_tracker[src_ip] = []

        # 3. Blacklist Check
        blacklist = ["192.168.1.100", "10.0.0.50"]
        if src_ip in blacklist:
            log_alert(src_ip, dst_ip, "IP", "Blacklisted IP Access", f"Connection attempt from: {src_ip}", "Critical", packet_size, tcp_flags)

def start_sniffing():
    print("🛡️ M-NIDS Sniffer Started... Monitoring network traffic.")
    # In Windows, you might need to specify the interface if default doesn't work.
    # sniff(prn=detect_attacks, store=0)
    sniff(prn=detect_attacks, store=0)

if __name__ == "__main__":
    start_sniffing()
