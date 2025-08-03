from scapy.all import sniff, IP, Raw

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        print(f"[+] Source: {src_ip} --> Destination: {dst_ip} | Protocol: {proto}")
        
        if Raw in packet:
            payload = packet[Raw].load
            print(f"    Payload: {payload[:50]}")  # Show first 50 bytes only
        print("-" * 50)

# Start sniffing packets (need root/admin privileges)
print("Sniffing started... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0)
