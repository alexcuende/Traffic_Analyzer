from scapy.all import rdpcap, sniff, wrpcap, IP, TCP
import matplotlib.pyplot as plt
import geoip2.database
from collections import Counter
import json
from datetime import datetime
import pyfiglet
import requests

text = "Made by Alex Cuende"
title = pyfiglet.figlet_format(text)
print(title)

GeoIP_DB_Path = 'GeoLite2-City.mmdb'
hec_url = "https://127.0.0.1:8088/services/collector"
hec_token = "b39a344e-3d3c-4554-830c-5976cb274400"

def capture_traffic(output_file='captured.pcap', count=1000):
    print("Currently capturing live traffic")
    packets = sniff(count=count)
    wrpcap(output_file, packets)
    print(f"Captured {count} packets to {output_file}")

def get_geo_info(ip, db_path=GeoIP_DB_Path):
    try:
        with geoip2.database.Reader(db_path) as reader:
            response = reader.city(ip)
            return f"{response.city.name}, {response.country.name}"
    except:
        return "Not able to find location"
    
def plot_activity(IP_counts):
    IPs = list(IP_counts.keys())
    counts = list(IP_counts.values())

    plt.figure(figsize=(12,6))
    plt.bar(IPs, counts, color='blue')
    plt.xticks(rotation=45, ha='right')
    plt.title("Suspicious activity IPs")
    plt.xlabel("IPs")
    plt.ylabel("Suspicious activities")
    plt.tight_layout()
    plt.show()

def analyze_pcap(file_path):
    packets = rdpcap(file_path)
    IP_activity = Counter()
    port_activity = Counter()
    SYN_activity = Counter()
    geo_info = {}
    suspicious_log = []

    print(f"Analyzing {file_path} with {len(packets)} packets")

    for packet in packets:
        if IP in packet and TCP in packet:
            source = packet[IP].src
            dest = packet[IP].dst
            destport = packet[TCP].dport
            flags = packet[TCP].flags
            # packet.show() if wanna see the contents of the packets

            suspicious = False

            if destport in [22, 23, 69, 135, 445, 3389]:
                print(f"Suspicious port {destport} accessed by {source}")
                port_activity[destport] += 1
                suspicious = True
            
            if packet[TCP].flags == 0x02: #Scapy doesn't allow us to use S for SYN
                print(f"SYN packet from {source} to {dest}:{destport}")
                SYN_activity[source] += 1
                suspicious = True
            
            if suspicious:
                suspicious_log.append({
                    "timestamp": datetime.now().isoformat(),
                    "source_IP": source,
                    "destination_IP": dest,
                    "destinantion_port": destport,
                    "reason": f"{'SYN packet' if packet[TCP].flags == 0x02 else 'Suspicious port'}"
                })
                IP_activity[source] += 1
                if source not in geo_info:
                    geo_info[source] = get_geo_info(source)

    send_to_splunk(suspicious_log, hec_url, hec_token)

    log_filename = f"suspicious_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(log_filename, "w") as f:
        json.dump(suspicious_log, f, indent=2)

    print("Suspicious summary")
    if not IP_activity:
        print("No suspicious activity")
    else:
        for ip, count in IP_activity.items():
            location = geo_info[ip]
            print(f"{ip}({location}) with {count} alerts")

        plot_activity(IP_activity)

def send_to_splunk(suspicious_log, hec_url, hec_token):
    try:
        print("Sending to splunk")
        payload = '\n'.join([json.dumps({"event": e, "sourcetype": "_json"}) for e in suspicious_log])
        headers = {
            'Authorization': f'Splunk {hec_token}',
            'Content-Type': 'application/json'
            }
        response = requests.post(hec_url, headers=headers, data=payload, verify=False)
        print(f"Splunk response: {response.status_code} - {response.text}")
        response.raise_for_status()
    except Exception as e:
        print(f"Error sending data to Splunk: {e}")



if __name__ == "__main__":
    import os

    live = input("Enable live capture? (Y/N): ").lower() == 'y'

    if live:
        capture_traffic()
        pcap_file = 'captured.pcap'
    else:
        pcap_file = input("Enter path to .pcap file: ")
        if not os.path.exists(pcap_file):
            print("File not found")
            exit()
    
    analyze_pcap(pcap_file)  