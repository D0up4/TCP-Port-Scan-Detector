from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time

connection_tracker = defaultdict(list)

ATTEMPT_THRESHOLD = 10
TIME_WINDOW = 10  # seconds

def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        timestamp = time.time()

        print(f"[DEBUG] Packet: {src_ip} -> port {dst_port}, flags={flags}")

        if flags == 0x02:  # SYN
            key = (src_ip, dst_port)
            connection_tracker[key].append(timestamp)
          
            recent_attempts = [t for t in connection_tracker[key] if timestamp - t <= TIME_WINDOW]
            connection_tracker[key] = recent_attempts

            if len(recent_attempts) > ATTEMPT_THRESHOLD:
                print(f"\n⚠️ Possible brute-force or DoS on port {dst_port} from {src_ip}")
                print(f"→ {len(recent_attempts)} SYN attempts in {TIME_WINDOW}s\n")
                connection_tracker[key] = []

def main():
    print("🔍 Monitoring for suspicious activity... Press Ctrl+C to stop.") 
    try:
        sniff(prn=packet_callback, filter="tcp", store=False)
    except KeyboardInterrupt:
        print("\n📊 Capture stopped.")

if __name__ == "__main__":
    main()
