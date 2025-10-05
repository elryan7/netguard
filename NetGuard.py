import os
import sys
import time
import socket
import logging
import threading
import ipaddress
import subprocess
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest


LOG_FILE = 'security_tool.log'
NETWORK_INTERFACE = 'eth0'
ALERT_THRESHOLD = 10  
INTRUSION_DETECTION_RULES = {
    'ICMP Flood': {'protocol': ICMP, 'threshold': 50},
    'SYN Flood': {'protocol': TCP, 'flags': 0x02, 'threshold': 100},
    'UDP Flood': {'protocol': UDP, 'threshold': 200}
}
RESPONSE_ACTIONS = {
    'block_ip': lambda ip: subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
}


logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')


ip_packet_count = defaultdict(int)
intrusion_detections = defaultdict(list)
anomaly_model = IsolationForest(contamination=0.01)

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_packet_count[ip_src] += 1
        logging.info(f"Paquet reçu de {ip_src}")

        for rule_name, rule in INTRUSION_DETECTION_RULES.items():
            if rule['protocol'] in packet and (rule.get('flags', 0) & packet[TCP].flags == rule['flags']):
                intrusion_detections[rule_name].append(ip_src)
                if len(intrusion_detections[rule_name]) > rule['threshold']:
                    logging.warning(f"Alerte {rule_name}: {ip_src}")
                    RESPONSE_ACTIONS['block_ip'](ip_src)

def monitor_network():
    try:
        sniff(iface=NETWORK_INTERFACE, prn=packet_callback, store=0)
    except Exception as e:
        logging.error(f"Erreur lors de la surveillance du réseau: {e}")

def check_alerts():
    while True:
        time.sleep(1)
        for ip, count in list(ip_packet_count.items()):
            if count > ALERT_THRESHOLD:
                logging.warning(f"Alerte: {ip} a envoyé plus de {ALERT_THRESHOLD} paquets par seconde.")
               
            ip_packet_count[ip] = 0 

def analyze_logs():
    try:
        with open(LOG_FILE, 'r') as file:
            for line in file:
                if 'Alerte' in line:
                    logging.warning(f"Incident détecté dans les journaux: {line}")
    except Exception as e:
        logging.error(f"Erreur lors de l'analyse des journaux: {e}")

def behavior_analysis():
    while True:
        time.sleep(60) 
        try:
            with open(LOG_FILE, 'r') as file:
                lines = file.readlines()
                if lines:
                    last_hour_lines = [line for line in lines if datetime.fromtimestamp(os.path.getmtime(LOG_FILE)) - timedelta(hours=1) <= datetime.strptime(line.split(' - ')[0], '%Y-%m-%d %H:%M:%S,%f')]
                    ip_activities = defaultdict(int)
                    for line in last_hour_lines:
                        if 'Paquet reçu de' in line:
                            ip = line.split('Paquet reçu de ')[1].strip()
                            ip_activities[ip] += 1
                    for ip, count in ip_activities.items():
                        if count > 1000:  
                            logging.warning(f"Comportement anormal détecté: {ip} a envoyé {count} paquets dans la dernière heure.")
        except Exception as e:
            logging.error(f"Erreur lors de l'analyse comportementale: {e}")

def update_dashboard():
    while True:
        time.sleep(60) 
        try:
            with open(LOG_FILE, 'r') as file:
                lines = file.readlines()
                if lines:
                    last_hour_lines = [line for line in lines if datetime.fromtimestamp(os.path.getmtime(LOG_FILE)) - timedelta(hours=1) <= datetime.strptime(line.split(' - ')[0], '%Y-%m-%d %H:%M:%S,%f')]
                    ip_activities = defaultdict(int)
                    for line in last_hour_lines:
                        if 'Paquet reçu de' in line:
                            ip = line.split('Paquet reçu de ')[1].strip()
                            ip_activities[ip] += 1

                    for widget in dashboard_frame.winfo_children():
                        widget.destroy()
                    for ip, count in ip_activities.items():
                        label = tk.Label(dashboard_frame, text=f"{ip}: {count} paquets")
                        label.pack()
        except Exception as e:
            logging.error(f"Erreur lors de la mise à jour du dashboard: {e}")

def generate_report():
    try:
        with open(LOG_FILE, 'r') as file:
            lines = file.readlines()
            report = []
            for line in lines:
                if 'Alerte' in line or 'Comportement anormal' in line:
                    report.append(line)
            with open('security_report.txt', 'w') as report_file:
                report_file.writelines(report)
            logging.info("Rapport de sécurité généré avec succès.")
    except Exception as e:
        logging.error(f"Erreur lors de la génération du rapport: {e}")

def create_ui():
    global dashboard_frame
    root = tk.Tk()
    root.title("Outil de Sécurité Réseau")

    dashboard_frame = tk.Frame(root)
    dashboard_frame.pack(pady=20)

    update_button = tk.Button(root, text="Mettre à jour le Dashboard", command=update_dashboard)
    update_button.pack(pady=10)

    report_button = tk.Button(root, text="Générer Rapport", command=generate_report)
    report_button.pack(pady=10)

    root.mainloop()

def main():

    network_thread = threading.Thread(target=monitor_network)
    network_thread.daemon = True
    network_thread.start()

    alert_thread = threading.Thread(target=check_alerts)
    alert_thread.daemon = True
    alert_thread.start()

    log_thread = threading.Thread(target=analyze_logs)
    log_thread.daemon = True
    log_thread.start()

    behavior_thread = threading.Thread(target=behavior_analysis)
    behavior_thread.daemon = True
    behavior_thread.start()

    ui_thread = threading.Thread(target=create_ui)
    ui_thread.daemon = True
    ui_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Arrêt de l'outil de sécurité.")

if __name__ == "__main__":
    main()
