from scapy.all import IP, TCP, ICMP, send, conf, get_if_list
import time
import sys
import socket

# Check for Npcap/WinPcap
if not conf.use_pcap:
    print("❌ ERROR: No libpcap provider found (Npcap/WinPcap).")
    print("M-NIDS requires Npcap to capture and send raw packets on Windows.")
    print("Please download and install Npcap from: https://npcap.com/")
    print("Make sure to check 'Install Npcap in WinPcap API-compatible Mode' during installation.")
    # sys.exit(1) # We can let it try, but it will likely fail.

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def simulate_icmp(target_ip):
    print(f"[SEND] Sending ICMP (Ping) packet to {target_ip}...")
    packet = IP(dst=target_ip)/ICMP()
    send(packet, verbose=False)
    print("DONE.")

def simulate_syn_scan(target_ip):
    print(f"[SCAN] Simulating SYN Scan (Port Scan) on {target_ip}...")
    for port in range(1024, 1035):
        packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(packet, verbose=False)
        time.sleep(0.1)
    print("✅ Done. (Sent 11 SYN packets)")

def simulate_blacklist_access(target_ip):
    print(f"[BLOCK] Simulating Blacklisted IP access...")
    print("To test this, send a packet from a machine with IP 192.168.1.100 or 10.0.0.50.")
    print("Alternatively, temporary add your own IP to the blacklist in sniffer.py.")

if __name__ == "__main__":
    target = get_local_ip()
    print(f"Targeting Local IP: {target}")
    
    available_ifs = get_if_list()
    if not available_ifs:
        print("⚠️ No network interfaces detected by Scapy.")
    
    print("\n--- M-NIDS Test Utility ---")
    print("1. Test ICMP Detection")
    print("2. Test SYN Scan Detection (Port Scan)")
    print("3. Exit")
    
    choice = input("Select an option (1-3): ")
    
    if choice == "1":
        simulate_icmp(target)
    elif choice == "2":
        simulate_syn_scan(target)
    elif choice == "3":
        sys.exit()
    else:
        print("Invalid choice.")
