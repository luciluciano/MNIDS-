import threading
import subprocess
import time
import sys
import os

def run_flask():
    print("🚀 Starting Web Dashboard...")
    subprocess.run(["python", "app.py"])

def run_sniffer():
    print("🛡️ Starting Packet Sniffer...")
    # Using subprocess to run sniffer.py as a separate process
    # This allows it to run with elevated privileges if needed separately
    subprocess.run(["python", "sniffer.py"])

if __name__ == "__main__":
    print("-" * 30)
    print("   M-NIDS (Mini Network IDS)   ")
    print("-" * 30)
    
    # Initialize DB first in case it's not done
    subprocess.run(["python", "init_db.py"])
    
    # Start threads
    flask_thread = threading.Thread(target=run_flask)
    sniffer_thread = threading.Thread(target=run_sniffer)
    
    flask_thread.start()
    sniffer_thread.start()
    
    print("\n✅ System is running!")
    print("👉 Dashboard: http://127.0.0.1:5000")
    print("👉 Press Ctrl+C to stop.\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down M-NIDS...")
        sys.exit(0)
