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
from tkinter import ttk, messagebox
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
import json
import requests
from playsound import playsound
from cryptography.fernet import Fernet
import base64
from web3 import Web3
from flask import Flask, request, jsonify
from keras.models import load_model
import numpy as np
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS, DNSQR

# Configuration
LOG_FILE = 'security_tool.log'
NETWORK_INTERFACE = 'eth0'
ALERT_THRESHOLD = 10  # Nombre maximum de paquets par seconde avant d'alerter
INTRUSION_DETECTION_RULES = {
    'ICMP Flood': {'protocol': ICMP, 'threshold': 50},
    'SYN Flood': {'protocol': TCP, 'flags': 0x02, 'threshold': 100},
    'UDP Flood': {'protocol': UDP, 'threshold': 200}
}
RESPONSE_ACTIONS = {
    'block_ip': lambda ip: subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
}
PUSH_NOTIFICATION_URL = 'https://api.pushnotifications.com/send'
SLACK_WEBHOOK_URL = 'https://hooks.slack.com/services/your/slack/webhook'
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)
BLOCKCHAIN_URL = 'http://localhost:8545'
web3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_URL))
contract_address = '0xYourContractAddress'
contract_abi = json.loads('''[{"constant":false,"inputs":[{"name":"_ip","type":"string"}],"name":"blockIP","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"}]''')
contract = web3.eth.contract(address=contract_address, abi=contract_abi)
ML_MODEL_PATH = 'anomaly_detection_model.h5'
ml_model = load_model(ML_MODEL_PATH)

# Initialisation du journal
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

# Dictionnaire pour suivre le nombre de paquets par adresse IP
ip_packet_count = defaultdict(int)
intrusion_detections = defaultdict(list)
anomaly_model = IsolationForest(contamination=0.01)

app = Flask(__name__)

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_packet_count[ip_src] += 1
        logging.info(f"Paquet reçu de {ip_src}")

        # Détection d'intrusion
        for rule_name, rule in INTRUSION_DETECTION_RULES.items():
            if rule['protocol'] in packet and (rule.get('flags', 0) & packet[TCP].flags == rule['flags']):
                intrusion_detections[rule_name].append(ip_src)
                if len(intrusion_detections[rule_name]) > rule['threshold']:
                    logging.warning(f"Alerte {rule_name}: {ip_src}")
                    RESPONSE_ACTIONS['block_ip'](ip_src)
                    send_alert(f"Alerte {rule_name} détectée de {ip_src}")
                    block_ip_on_blockchain(ip_src)

        # Analyse comportementale avec ML
        if HTTPRequest in packet:
            http_payload = packet[HTTPRequest].load
            features = extract_features(http_payload)
            prediction = ml_model.predict(np.array([features]))
            if prediction[0] == 1:
                logging.warning(f"Comportement anormal détecté: {ip_src}")
                send_alert(f"Comportement anormal détecté: {ip_src}")

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
                send_alert(f"Alerte: {ip} a envoyé plus de {ALERT_THRESHOLD} paquets par seconde.")
                # Ajoutez ici la logique pour répondre à l'incident
            ip_packet_count[ip] = 0  # Réinitialiser le compteur

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
        time.sleep(60)  # Analyse comportementale toutes les 60 secondes
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
                        if count > 1000:  # Seuil pour l'analyse comportementale
                            logging.warning(f"Comportement anormal détecté: {ip} a envoyé {count} paquets dans la dernière heure.")
                            send_alert(f"Comportement anormal détecté: {ip} a envoyé {count} paquets dans la dernière heure.")
        except Exception as e:
            logging.error(f"Erreur lors de l'analyse comportementale: {e}")

def update_dashboard():
    while True:
        time.sleep(60)  # Mise à jour du dashboard toutes les 60 secondes
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
                    # Mise à jour du dashboard
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

def send_alert(message):
    # Notification push
    payload = {'message': message}
    requests.post(PUSH_NOTIFICATION_URL, json=payload)

    # Alertes Slack
    slack_payload = {'text': message}
    requests.post(SLACK_WEBHOOK_URL, json=slack_payload)

    # Alerte sonore
    playsound('alert.wav')

def integrate_with_other_tools():
    # Exemple d'intégration avec une API de sécurité externe
    external_api_url = 'https://api.externalsecuritytool.com/alert'
    while True:
        time.sleep(60)
        try:
            with open(LOG_FILE, 'r') as file:
                lines = file.readlines()
                for line in lines:
                    if 'Alerte' in line or 'Comportement anormal' in line:
                        payload = {'alert': line}
                        requests.post(external_api_url, json=payload)
        except Exception as e:
            logging.error(f"Erreur lors de l'intégration avec d'autres outils: {e}")

def incident_management():
    incident_log = 'incident_log.json'
    if not os.path.exists(incident_log):
        with open(incident_log, 'w') as f:
            json.dump([], f)
    while True:
        time.sleep(60)
        try:
            with open(LOG_FILE, 'r') as file:
                lines = file.readlines()
                new_incidents = []
                for line in lines:
                    if 'Alerte' in line or 'Comportement anormal' in line:
                        incident = {
                            'timestamp': datetime.now().isoformat(),
                            'message': line.strip()
                        }
                        new_incidents.append(incident)
                with open(incident_log, 'r+') as f:
                    incidents = json.load(f)
                    incidents.extend(new_incidents)
                    f.seek(0)
                    json.dump(incidents, f, indent=4)
                    f.truncate()
        except Exception as e:
            logging.error(f"Erreur lors de la gestion des incidents: {e}")

def visualize_data():
    while True:
        time.sleep(300)  # Mise à jour des visualisations toutes les 5 minutes
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
                    plt.figure(figsize=(10, 5))
                    plt.bar(ip_activities.keys(), ip_activities.values())
                    plt.xticks(rotation=90)
                    plt.title('Activités Réseau des Dernières 60 Minutes')
                    plt.xlabel('Adresse IP')
                    plt.ylabel('Nombre de Paquets')
                    plt.tight_layout()
                    plt.savefig('network_activity.png')
                    plt.close()
        except Exception as e:
            logging.error(f"Erreur lors de la visualisation des données: {e}")

def encrypt_logs():
    while True:
        time.sleep(3600)  # Chiffrement des journaux toutes les heures
        try:
            with open(LOG_FILE, 'rb') as file:
                data = file.read()
            encrypted_data = cipher_suite.encrypt(data)
            with open(LOG_FILE, 'wb') as file:
                file.write(encrypted_data)
        except Exception as e:
            logging.error(f"Erreur lors du chiffrement des journaux: {e}")

def decrypt_logs():
    try:
        with open(LOG_FILE, 'rb') as file:
            data = file.read()
        decrypted_data = cipher_suite.decrypt(data)
        with open(LOG_FILE, 'wb') as file:
            file.write(decrypted_data)
    except Exception as e:
        logging.error(f"Erreur lors du déchiffrement des journaux: {e}")

def block_ip_on_blockchain(ip):
    try:
        tx_hash = contract.functions.blockIP(ip).transact({'from': web3.eth.accounts[0]})
        web3.eth.wait_for_transaction_receipt(tx_hash)
        logging.info(f"Adresse IP {ip} bloquée sur la blockchain.")
    except Exception as e:
        logging.error(f"Erreur lors du blocage de l'adresse IP {ip} sur la blockchain: {e}")

def identity_and_access_management():
    while True:
        time.sleep(3600)  # Gestion des identités et des accès toutes les heures
        try:
            # Exemple de vérification des accès
            with open('access_log.json', 'r') as file:
                access_logs = json.load(file)
            for log in access_logs:
                if log['status'] == 'failed':
                    logging.warning(f"Échec d'accès détecté: {log}")
                    send_alert(f"Échec d'accès détecté: {log}")
        except Exception as e:
            logging.error(f"Erreur lors de la gestion des identités et des accès: {e}")

def disaster_recovery():
    while True:
        time.sleep(86400)  # Récupération après sinistre toutes les 24 heures
        try:
            # Exemple de sauvegarde des données
            with open(LOG_FILE, 'r') as file:
                data = file.read()
            with open('backup_log.txt', 'w') as backup_file:
                backup_file.write(data)
            logging.info("Sauvegarde des données effectuée avec succès.")
        except Exception as e:
            logging.error(f"Erreur lors de la récupération après sinistre: {e}")

@app.route('/api/alerts', methods=['POST'])
def receive_alerts():
    data = request.json
    logging.warning(f"Alerte reçue via API: {data}")
    return jsonify({"status": "success"})

def extract_features(payload):
    # Exemple de fonction pour extraire des caractéristiques du payload HTTP
    features = []
    # Ajoutez ici la logique pour extraire les caractéristiques pertinentes
    features.append(len(payload))
    features.append(payload.count('GET'))
    features.append(payload.count('POST'))
    return features

def main():
    # Démarrer la surveillance du réseau dans un thread séparé
    network_thread = threading.Thread(target=monitor_network)
    network_thread.daemon = True
    network_thread.start()

    # Démarrer la vérification des alertes dans un thread séparé
    alert_thread = threading.Thread(target=check_alerts)
    alert_thread.daemon = True
    alert_thread.start()

    # Démarrer l'analyse des journaux dans un thread séparé
    log_thread = threading.Thread(target=analyze_logs)
    log_thread.daemon = True
    log_thread.start()

    # Démarrer l'analyse comportementale dans un thread séparé
    behavior_thread = threading.Thread(target=behavior_analysis)
    behavior_thread.daemon = True
    behavior_thread.start()

    # Démarrer l'interface utilisateur dans un thread séparé
    ui_thread = threading.Thread(target=create_ui)
    ui_thread.daemon = True
    ui_thread.start()

    # Démarrer l'intégration avec d'autres outils dans un thread séparé
    integration_thread = threading.Thread(target=integrate_with_other_tools)
    integration_thread.daemon = True
    integration_thread.start()

    # Démarrer la gestion des incidents dans un thread séparé
    incident_thread = threading.Thread(target=incident_management)
    incident_thread.daemon = True
    incident_thread.start()

    # Démarrer la visualisation des données dans un thread séparé
    visualize_thread = threading.Thread(target=visualize_data)
    visualize_thread.daemon = True
    visualize_thread.start()

    # Démarrer le chiffrement des journaux dans un thread séparé
    encrypt_thread = threading.Thread(target=encrypt_logs)
    encrypt_thread.daemon = True
    encrypt_thread.start()

    # Démarrer la gestion des identités et des accès dans un thread séparé
    iam_thread = threading.Thread(target=identity_and_access_management)
    iam_thread.daemon = True
    iam_thread.start()

    # Démarrer la récupération après sinistre dans un thread séparé
    dr_thread = threading.Thread(target=disaster_recovery)
    dr_thread.daemon = True
    dr_thread.start()

    # Démarrer l'API Flask
    api_thread = threading.Thread(target=app.run, kwargs={'host': '0.0.0.0', 'port': 5000})
    api_thread.daemon = True
    api_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Arrêt de l'outil de sécurité.")
        decrypt_logs()

if __name__ == "__main__":
    main()
