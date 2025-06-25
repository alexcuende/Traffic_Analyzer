# Traffic_Analyzer

Traffic Analyzer is a Python-based network forensics tool that analyzes .pcap files or live traffic to detect and visualize potentially suspicious activities. It flags common attack indicators like SYN scans and sensitive port access, geolocates IP addresses, generates visual reports, and sends event data to Splunk via HEC.

How to install:

<pre>git clone https://github.com/alexcuende/traffic_analyzer.git 
cd traffic_analyzer 
pip install -r requirements.txt </pre>

How to use:
<pre>python traffic_analyzer.py</pre>

A GUI will appear enabling you to interact without the command prompt.

![image](https://github.com/user-attachments/assets/4a6f993c-f094-4cf9-9e75-d7b9e7b6f3fc)

MAKE SURE YOUR SPLUNK IS CORRECTLY INTEGRATED:

<pre>SPLUNK_HEC_URL = "https://127.0.0.1:8088/services/collector"

SPLUNK_HEC_TOKEN = "your-hec-token-here"</pre>

AND YOUR AbuseIDPB token:

<pre>ABUSEIPDB_API_KEY = "your-APIKEY-here</pre>
