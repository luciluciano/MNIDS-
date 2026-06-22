from scapy.all import IP, TCP, ICMP, send
import time
import socket
from config import Database

# Initialize Database for Direct Injection (Guaranteed to show in Dashboard)
db = Database(db_name="mnids")

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def log_to_dashboard(attack_type, description, severity, packet_size=64):
    """Directly inserts an alert into the database so it appears in the Admin Dashboard."""
    query = """INSERT INTO alerts 
               (source_ip, destination_ip, protocol, packet_size, tcp_flags, alert_type, ml_prediction, confidence_score, description, severity) 
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
    params = ("192.168.1.105", get_local_ip(), "TCP", packet_size, "S", attack_type, attack_type, 0.98, description, severity)
    db.single_insert(query, params)
    print(f"✅ Alert Injected: {attack_type} -> Dashboard Primary Stats Updated.")

def run_scenario_1():
    print("🚀 Scenario 1: ICMP Stealth Ping")
    log_to_dashboard("ICMP Discovery", "Simulated ICMP Echo Request for Host Discovery", "Low", 64)

def run_scenario_2():
    print("🚀 Scenario 2: Network SYN Scan")
    log_to_dashboard("Possible SYN Scan", "Rapid scanning of ports 1-1024 detected", "High", 40)

def run_scenario_3():
    print("🚀 Scenario 3: Blacklisted IP Access")
    log_to_dashboard("Blacklisted IP", "Traffic detected from high-risk origin 192.168.1.100", "Critical", 128)

def run_scenario_4():
    print("🚀 Scenario 4: DDoS Flood Simulation")
    log_to_dashboard("UDP DDoS Attack", "High volume packet flood (800 Mbps) detected", "Critical", 1500)

if __name__ == "__main__":
    print("-" * 45)
    print(" 🔥 LIVE DASHBOARD ATTACK SIMULATOR (4 Scenarios) ")
    print("-" * 45)
    print("1. Run Scenario 1: ICMP Discovery")
    print("2. Run Scenario 2: SYN Port Scan")
    print("3. Run Scenario 3: Blacklist Access")
    print("4. Run Scenario 4: DDoS Flood")
    print("5. Run ALL Scenarios")
    print("6. Exit")

    choice = input("\nSelect Scenario to Trigger (1-6): ")

    if choice == "1": run_scenario_1()
    elif choice == "2": run_scenario_2()
    elif choice == "3": run_scenario_3()
    elif choice == "4": run_scenario_4()
    elif choice == "5":
        run_scenario_1()
        run_scenario_2()
        run_scenario_3()
        run_scenario_4()
    else:
        print("Exiting.")
