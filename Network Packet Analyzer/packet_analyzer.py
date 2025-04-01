from scapy.all import sniff, IP, TCP, UDP

# Function to process captured packets
def packet_callback(packet):
    # If the packet has an IP layer
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        # Display packet information
        if packet.haslayer(TCP):
            protocol = 'TCP'
        elif packet.haslayer(UDP):
            protocol = 'UDP'
        
        # Print packet details
        print("=" * 60)
        print(f"Packet captured!")
        print(f"Source IP      : {ip_src}")
        print(f"Destination IP : {ip_dst}")
        print(f"Protocol       : {protocol}")

        # Handle payloads
        payload = packet.payload
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
        print(f"Payload        : {payload}")
        print("=" * 60)

# Start packet sniffing
def start_sniffing():
    try:
        # Start sniffing network traffic (capture 50 packets for testing)
        sniff(prn=packet_callback, store=0, count=50)
    except Exception as e:
        print(f"An error occurred: {str(e)}")

# Run the sniffing
start_sniffing()
