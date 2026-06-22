from scapy.all import IP, UDP, TCP, send, conf
import time
import random
import socket

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def simulate_udp_flood(target_ip, duration=5):
    print(f"🔥 [ATTACK] Starting UDP Flood on {target_ip} for {duration} seconds...")
    timeout = time.time() + duration
    sent = 0
    while time.time() < timeout:
        # High volume, varied ports
        packet = IP(dst=target_ip)/UDP(dport=random.randint(1, 65535))/("X" * 1024)
        send(packet, verbose=False)
        sent += 1
        if sent % 50 == 0:
            print(f" - Sent {sent} packets...")
    print(f"✅ UDP Flood Complete. Total packets: {sent}")

def simulate_xmas_scan(target_ip):
    print(f"🕵️ [STEALTH] Simulating XMAS Scan (FIN+PSH+URG) on {target_ip}...")
    # Xmas scans use illegal combinations of flags to bypass simple firewalls
    for port in [21, 22, 23, 80, 443, 3306]:
        packet = IP(dst=target_ip)/TCP(dport=port, flags="FPU")
        send(packet, verbose=False)
        time.sleep(0.2)
    print("✅ XMAS Scan Complete.")

if __name__ == "__main__":
    target = get_local_ip()
    print("-" * 35)
    print(f" M-NIDS ADVANCED ATTACK SIMULATOR ")
    print("-" * 35)
    print(f"Targeting Local Host: {target}\n")
    print("1. UDP Flood (DDoS Test)")
    print("2. XMAS Scan (Stealth Anomaly Test)")
    print("3. Exit")
    
    choice = input("\nSelect target attack (1-3): ")
    
    if choice == "1":
        simulate_udp_flood(target)
    elif choice == "2":
        simulate_xmas_scan(target)
    else:
        print("Exiting.")
