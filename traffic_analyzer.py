import tkinter as tk
from tkinter import messagebox, simpledialog
from scapy.all import sniff, wrpcap, rdpcap, IP, TCP
from collections import Counter
from datetime import datetime
import threading
import requests
import matplotlib.pyplot as plt
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_HEC_URL = "https://127.0.0.1:8088/services/collector"
SPLUNK_HEC_TOKEN = "ENTER HEC_TOKEN"
ABUSEIPDB_API_KEY = 'ENTER_APIKEY'

SUSPICIOUS_PORTS = [22, 23, 69, 135, 445, 3389]

IP_activity = Counter()
analysis_log = []
is_capturing = False

def start_live_capture(): # Method to start thread while capturing data to allow the GUI be operative at the same time
    global is_capturing
    if is_capturing:
        return
    is_capturing = True
    status_label.config(text="Capturing packets...", fg="orange")
    threading.Thread(target=run_capture, daemon=True).start()

def run_capture(): # Method to start the capture of data, change the count to make a bigger/smaller capture
    try:
        packets = sniff(count=1500)
        filename = f"captured_{datetime.now().strftime('%H%M%S')}.pcap"
        wrpcap(filename, packets)
        status_label.config(text=f"Captured and saved to {filename}", fg="lightgreen")
        analyze_pcap(filename)
    except Exception as e:
        messagebox.showerror("Error", f"Capture failed: {e}")
    finally:
        global is_capturing
        is_capturing = False

def analyze_pcap(path): # Method to analyze the data
    global IP_activity, analysis_log
    IP_activity = Counter()
    analysis_log = []

    hosts_list.delete(0, tk.END)
    try:
        packets = rdpcap(path)
    except Exception as e:
        messagebox.showerror("Error", f"Could not read PCAP:\n{e}")
        return

    for pkt in packets:
        if IP in pkt and TCP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            dport = pkt[TCP].dport
            flags = pkt[TCP].flags

            suspicious_ips = set()
            reason = None

           
            if dport in SUSPICIOUS_PORTS:
                reason = f"Suspicious Port: {dport}"
                suspicious_ips.update([src, dst])
            elif flags == 0x02:
                reason = "SYN Packet"
                suspicious_ips.update([src, dst])

            if reason:
                log_entry = f"[{datetime.now().strftime('%H:%M:%S')}] {src} → {dst}:{dport} | {reason}"
                analysis_log.append(log_entry)
                for ip in suspicious_ips:
                    IP_activity[ip] += 1

                send_event_to_splunk({
                    "timestamp": datetime.now().isoformat(),
                    "src_ip": src,
                    "dst_ip": dst,
                    "dest_port": dport,
                    "reason": reason
                })

    if not analysis_log:
        hosts_list.insert(tk.END, "No suspicious activity found.")
        status_label.config(text="Analysis complete", fg="lightgreen")
    else:
        for entry in analysis_log:
            hosts_list.insert(tk.END, entry)
        status_label.config(text=f"Found {len(analysis_log)} suspicious entries", fg="orange")

def browse_pcap(): # Method to look for .pcap files on your device
    from tkinter import filedialog
    file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
    if file_path:
        analyze_pcap(file_path)

def show_graph(): # Method to create the graph
    if not IP_activity:
        messagebox.showinfo("Graph", "No suspicious IPs to display.")
        return

    plt.figure(figsize=(12, 6))
    plt.bar(IP_activity.keys(), IP_activity.values(), color='cyan')
    plt.title("Suspicious Activity by IP")
    plt.xlabel("IP Address")
    plt.ylabel("Alerts")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

def send_event_to_splunk(event_message): # Method to send to splunk, Remember to activate HTTP.eventcollector
    headers = {
        'Authorization': f'Splunk {SPLUNK_HEC_TOKEN}',
        'Content-Type': 'application/json'
    }
    payload = {
        "event": event_message,
        "sourcetype": "_json",
        "source": "traffic_analyzer",
        "host": "local_machine"
    }
    try:
        response = requests.post(SPLUNK_HEC_URL, headers=headers, data=json.dumps(payload), verify=False)
        if response.status_code != 200:
            print(f"Splunk HEC error: {response.text}")
    except Exception as e:
        print(f"Failed to send event to Splunk: {e}")

def lookup_abuseipdb(ip): # Method to check in AbuseIPDB
    if not ABUSEIPDB_API_KEY:
        messagebox.showwarning("API Key Missing", "Please set your AbuseIPDB API key in the script.")
        return

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY,
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()
        if 'data' in data:
            abuse_data = data['data']
            msg = (f"IP: {abuse_data['ipAddress']}\n"
                   f"Abuse Confidence Score: {abuse_data['abuseConfidenceScore']}\n"
                   f"Total Reports: {abuse_data['totalReports']}\n"
                   f"Last Reported: {abuse_data.get('lastReportedAt', 'N/A')}\n"
                   f"Country: {abuse_data.get('countryCode', 'N/A')}\n"
                   f"Usage Type: {abuse_data.get('usageType', 'N/A')}\n"
                   f"ISP: {abuse_data.get('isp', 'N/A')}\n"
                   f"Domain: {abuse_data.get('domain', 'N/A')}")
            messagebox.showinfo(f"AbuseIPDB Info for {ip}", msg)
        else:
            messagebox.showinfo("AbuseIPDB", f"No data found or incorrect format for IP {ip}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to get data from AbuseIPDB:\n{e}")

def on_lookup_button(): # Method for getting the correct IP and send to AbuseIPDB
    ip = ip_entry.get().strip()
    if not ip:
        selection = hosts_list.curselection()
        if selection:
            selected_text = hosts_list.get(selection[0])
            parts = selected_text.split()
            for part in parts:
                if part.count('.') == 3:
                    ip = part
                    break
    if not ip:
        messagebox.showwarning("Input needed", "Please enter an IP or select an entry in the list.")
        return
    lookup_abuseipdb(ip)

#GUI
window = tk.Tk()
window.title("Traffic Analyzer")
window.geometry("900x900")
window.configure(bg="#000000")

label_style = {"bg": "#000000", "fg": "lightgreen", "font": ("Consolas", 16)}
btn_style = {"bg": "#333", "fg": "#fff", "activebackground": "#555", "font": ("Consolas", 14), "width": 18}

tk.Label(window, text="Traffic Analyzer", font=("Consolas", 20), fg="#0dff00", bg="#000000").pack(pady=10)

btn_frame = tk.Frame(window, bg="#000000")
btn_frame.pack(pady=10)

tk.Button(btn_frame, text="Start Live Capture", command=start_live_capture, **btn_style).grid(row=0, column=0, padx=6)
tk.Button(btn_frame, text="Import .pcap File", command=browse_pcap, **btn_style).grid(row=0, column=1, padx=6)
tk.Button(btn_frame, text="Get Graph", command=show_graph, **btn_style).grid(row=0, column=2, padx=6)

lookup_frame = tk.Frame(window, bg="#000000")
lookup_frame.pack(pady=10)

tk.Label(lookup_frame, text="IP for AbuseIPDB lookup:", **label_style).grid(row=0, column=0, padx=5, sticky='e')
ip_entry = tk.Entry(lookup_frame, width=30, bg="#2a2a2a", fg="#00ff88", insertbackground="#00ff88", font=("Consolas", 16))
ip_entry.grid(row=0, column=1, padx=5)
tk.Button(lookup_frame, text="Lookup AbuseIPDB", command=on_lookup_button, **btn_style).grid(row=0, column=2, padx=6)

status_label = tk.Label(window, text="Waiting for input...", **label_style)
status_label.pack(pady=10)

tk.Label(window, text="Suspicious Traffic Log:", **label_style).pack()
hosts_list = tk.Listbox(window, height=20, width=110, bg="#000000", fg="#00ff88", font=("Consolas", 10), bd=2)
hosts_list.pack(pady=10)

window.mainloop()
