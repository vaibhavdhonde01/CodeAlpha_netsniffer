from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    try:
        if IP in packet:
            ip_layer = packet[IP]
            print(f"[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")

            if TCP in packet:
                tcp_layer = packet[TCP]
                print(f"[+] TCP Packet: {tcp_layer.sport} -> {tcp_layer.dport}")

            elif UDP in packet:
                udp_layer = packet[UDP]
                print(f"[+] UDP Packet: {udp_layer.sport} -> {udp_layer.dport}")

            print(f"[+] Protocol: {ip_layer.proto}")

            # Print the payload if it exists
            if Raw in packet:
                raw_layer = packet[Raw]
                print(f"[+] Payload: {raw_layer.load}")

    except Exception as e:
        print(f"[!] Error processing packet: {e}")

def main():
    print("[+] Starting network sniffer...")
    # Specify the network interface (e.g., 'eth0' for Linux, 'en0' for macOS)
    interface = 'eth0'

    # Specify the source IP address to filter
    source_ip = '192.168.233.128'  # Replace with the source IP address you want to filter

    # Create the filter expression for the source IP address
    filter_expression = f"src {source_ip}"

    try:
        sniff(iface=interface, prn=packet_callback, store=0, filter=filter_expression)
    except Exception as e:
        print(f"[!] Error starting sniffer: {e}")

if __name__ == "__main__":
    main()