import pandas as pd
import numpy as np
import os

def generate_csv(filename, num_rows, scenario_type):
    data = []
    
    for _ in range(num_rows):
        if scenario_type == 'normal':
            # Normal traffic: varying packet sizes, mostly TCP/UDP, low threats
            packet_size = np.random.randint(60, 1500)
            protocol = np.random.choice(['TCP', 'UDP', 'ICMP'])
            flags = np.random.choice(['A', 'PA', 'S', 'FA', ''])
            duration = np.random.uniform(0.1, 5.0)
        elif scenario_type == 'ddos':
            # DDoS: large packets or high frequency, specific protocols
            packet_size = 1500
            protocol = 'UDP'
            flags = ''
            duration = np.random.uniform(0.001, 0.05)
        elif scenario_type == 'syn_scan':
            # SYN Scan: small packets, SYN flag
            packet_size = 64
            protocol = 'TCP'
            flags = 'S'
            duration = np.random.uniform(0.001, 0.01)
        elif scenario_type == 'icmp_flood':
            # ICMP Flood
            packet_size = 98
            protocol = 'ICMP'
            flags = ''
            duration = np.random.uniform(0.01, 0.05)
        elif scenario_type == 'exfiltration':
            # Data Exfiltration: very large byte counts (reflected in packet size here)
            packet_size = np.random.randint(1400, 1500)
            protocol = 'TCP'
            flags = 'PA'
            duration = np.random.uniform(5.0, 60.0)
        else: # mixed
            if np.random.random() > 0.8:
                packet_size = 1500
                protocol = 'UDP'
                flags = ''
            else:
                packet_size = np.random.randint(60, 500)
                protocol = 'TCP'
                flags = 'A'
            duration = np.random.uniform(0.1, 1.0)

        data.append({
            'packet_size': packet_size,
            'protocol': protocol,
            'tcp_flags': flags,
            'duration': duration,
            'source_ip': f"192.168.1.{np.random.randint(2, 254)}",
            'dest_ip': "10.0.0.5"
        })

    df = pd.DataFrame(data)
    df.to_csv(os.path.join('sample_data', filename), index=False)
    print(f"Generated: {filename} ({scenario_type})")

# Generate 10 variations
scenarios = [
    ('traffic_normal_1.csv', 50, 'normal'),
    ('traffic_normal_2.csv', 100, 'normal'),
    ('attack_ddos_high_volume.csv', 200, 'ddos'),
    ('scan_syn_stealth.csv', 150, 'syn_scan'),
    ('attack_icmp_flood.csv', 80, 'icmp_flood'),
    ('data_exfiltration_detect.csv', 40, 'exfiltration'),
    ('traffic_mixed_daily.csv', 120, 'mixed'),
    ('scan_port_discovery.csv', 90, 'syn_scan'),
    ('traffic_office_hours.csv', 60, 'normal'),
    ('attack_malicious_burst.csv', 50, 'mixed')
]

if __name__ == "__main__":
    if not os.path.exists('sample_data'):
        os.makedirs('sample_data')
    for filename, rows, stype in scenarios:
        generate_csv(filename, rows, stype)
