# Traffic_Analyzer

Traffic Analyzer is a Python-based network forensics tool that analyzes .pcap files or live traffic to detect and visualize potentially suspicious activities. It flags common attack indicators like SYN scans and sensitive port access, geolocates IP addresses, generates visual reports, and sends event data to Splunk via HEC.

How to install:

git clone https://github.com/alexcuende/traffic_analyzer.git
cd traffic-analyzer

pip install -r requirements.txt

How to use:

python traffic_analyzer.py

when prompted, Enable live capture? (Y/N): n
Enter path to .pcap file: example.pcap

(if want live traffic just say y instead of n)

MAKE SURE YOUR SPLUNK IS CORRECTLY INTEGRATED:

hec_url = "https://127.0.0.1:8088/services/collector"
hec_token = "your-hec-token-here"
