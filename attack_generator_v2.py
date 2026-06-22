import pandas as pd
import numpy as np
import os

def generate_scenarios():
    output_dir = "attack_scenarios"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    print(f"🚀 Generating 4 Security Scenarios in '{output_dir}/'...")

    # 1. Normal Traffic
    normal_data = {
        'packet_size': np.random.randint(64, 1500, 100),
        'protocol': ['TCP'] * 60 + ['UDP'] * 30 + ['ICMP'] * 10,
        'tcp_flags': ['S'] * 20 + ['A'] * 40 + [''] * 40,
        'duration': np.random.uniform(0.1, 5.0, 100)
    }
    pd.DataFrame(normal_data).to_csv(f"{output_dir}/scenario_1_normal.csv", index=False)
    print("✅ Created: scenario_1_normal.csv")

    # 2. SYN Scan Attack
    syn_scan_data = {
        'packet_size': [66] * 80 + [120] * 20,
        'protocol': ['TCP'] * 100,
        'tcp_flags': ['S'] * 80 + ['A'] * 20,
        'duration': np.random.uniform(0.01, 0.05, 100)
    }
    pd.DataFrame(syn_scan_data).to_csv(f"{output_dir}/scenario_2_syn_scan.csv", index=False)
    print("✅ Created: scenario_2_syn_scan.csv")

    # 3. ICMP Flood Attack
    icmp_flood_data = {
        'packet_size': [98] * 90 + [64] * 10,
        'protocol': ['ICMP'] * 90 + ['TCP'] * 10,
        'tcp_flags': [''] * 100,
        'duration': np.random.uniform(0.001, 0.01, 100)
    }
    pd.DataFrame(icmp_flood_data).to_csv(f"{output_dir}/scenario_3_icmp_flood.csv", index=False)
    print("✅ Created: scenario_3_icmp_flood.csv")

    # 4. DDoS Attack (UDP Flood)
    ddos_data = {
        'packet_size': [1500] * 95 + [64] * 5,
        'protocol': ['UDP'] * 95 + ['TCP'] * 5,
        'tcp_flags': [''] * 100,
        'duration': np.random.uniform(0.0001, 0.001, 100)
    }
    pd.DataFrame(ddos_data).to_csv(f"{output_dir}/scenario_4_ddos.csv", index=False)
    print("✅ Created: scenario_4_ddos.csv")

    print("\n✨ All scenarios generated successfully! Use these CSVs to test the ML-NIDS system.")

if __name__ == "__main__":
    generate_scenarios()
