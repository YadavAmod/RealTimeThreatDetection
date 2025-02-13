import psutil
import time
import numpy as np
import socket
import threading
import logging
import os
import json
import requests
import subprocess
import platform
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import multiprocessing
import sys
import colorama
from tabulate import tabulate
import queue

# Initialize colorama for colored output
colorama.init(autoreset=True)

# Advanced Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler('threat_detection.log'),
        logging.StreamHandler()
    ]
)

# Enhanced Configuration
class ThreatDetectionConfig:
    MONITORING_INTERVAL = 1  # seconds
    ANOMALY_THRESHOLD = -0.5  # More sensitive threshold
    MODEL_FILENAME = 'advanced_anomaly_model.pkl'
    ALERT_WEBHOOK_URL = None  # Optional Slack/Discord webhook
    MAX_HISTORICAL_DATA = 1000  # Max historical data points
    CRITICAL_PROCESSES = [
        'sshd', 'nginx', 'apache2', 'mysqld', 'postfix'
    ]

# User Interaction Queue for Real-Time Updates
class UserOutputQueue:
    def __init__(self):
        self.queue = queue.Queue()
        self.running = True

    def add_message(self, message, message_type='info'):
        """Add a message to the queue with a type."""
        if self.running:
            self.queue.put((message_type, message))

    def display_messages(self):
        """Display messages from the queue with color coding."""
        while self.running:
            try:
                message_type, message = self.queue.get(timeout=1)
                if message_type == 'threat':
                    print(colorama.Fore.RED + f"🚨 THREAT ALERT: {message}")
                elif message_type == 'warning':
                    print(colorama.Fore.YELLOW + f"⚠️ WARNING: {message}")
                else:
                    print(colorama.Fore.GREEN + f"ℹ️ INFO: {message}")
            except queue.Empty:
                time.sleep(0.1)

    def stop(self):
        """Stop the message display."""
        self.running = False

# Global User Output Queue
user_output_queue = UserOutputQueue()

# Advanced Feature Extraction
class SystemFeatureExtractor:
    @staticmethod
    def get_comprehensive_system_metrics():
        """Collect a wide range of system metrics."""
        metrics = {
            'CPU Usage': f"{psutil.cpu_percent(interval=1)}%",
            'Memory Usage': f"{psutil.virtual_memory().percent}%",
            'Disk Usage': f"{psutil.disk_usage('/').percent}%",
            'Network Sent': f"{psutil.net_io_counters().bytes_sent} bytes",
            'Network Received': f"{psutil.net_io_counters().bytes_recv} bytes",
            'Active Connections': len(psutil.net_connections()),
            'Running Processes': len(psutil.pids()),
            'System Load': os.getloadavg()[0] if hasattr(os, 'getloadavg') else 0
        }
        return metrics

    @staticmethod
    def check_critical_processes():
        """Monitor critical system processes."""
        critical_running = []
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] in ThreatDetectionConfig.CRITICAL_PROCESSES:
                critical_running.append(proc.info['name'])
        return critical_running

# Advanced Network Security
class NetworkSecurityAnalyzer:
    @staticmethod
    def scan_open_ports(host='localhost', max_port=1024):
        """Perform a basic port scan to identify open ports."""
        open_ports = []
        for port in range(1, max_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return open_ports

    @staticmethod
    def analyze_network_connections():
        """Analyze current network connections."""
        connections = psutil.net_connections()
        suspicious_connections = [
            conn for conn in connections 
            if conn.status == 'ESTABLISHED' and conn.raddr
        ]
        return suspicious_connections

# Enhanced Anomaly Detection
class AdvancedAnomalyDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = None
        self.historical_data = []

    def prepare_data(self):
        """Prepare and scale data for anomaly detection."""
        if len(self.historical_data) < 10:
            return None
        
        data_array = np.array(self.historical_data)
        scaled_data = self.scaler.fit_transform(data_array)
        return scaled_data

    def train_model(self, data):
        """Train an advanced anomaly detection model."""
        if data is None:
            return None
        
        self.model = IsolationForest(
            contamination='auto', 
            random_state=42, 
            max_samples='auto'
        )
        self.model.fit(data)
        joblib.dump(self.model, ThreatDetectionConfig.MODEL_FILENAME)
        logging.info("Advanced anomaly model trained and saved.")
        return self.model

    def detect_anomalies(self, new_data):
        """Detect anomalies in system metrics."""
        if self.model is None:
            return False
        
        scaled_new_data = self.scaler.transform([new_data])
        anomaly_score = self.model.decision_function(scaled_new_data)[0]
        
        return anomaly_score <= ThreatDetectionConfig.ANOMALY_THRESHOLD

# Modified Alert Mechanism
def send_threat_alert(threat_details):
    """Send alerts via multiple channels."""
    # Display detailed threat information in a tabular format
    threat_table = tabulate(
        threat_details.items(), 
        headers=['Attribute', 'Value'], 
        tablefmt='pretty'
    )
    
    # Add to user output queue
    user_output_queue.add_message(f"\n{threat_table}", 'threat')
    
    # Slack/Discord webhook (optional)
    if ThreatDetectionConfig.ALERT_WEBHOOK_URL:
        try:
            requests.post(
                ThreatDetectionConfig.ALERT_WEBHOOK_URL, 
                json={'text': json.dumps(threat_details)}
            )
        except Exception as e:
            user_output_queue.add_message(f"Alert webhook failed: {e}", 'warning')

# Main Monitoring Function
def advanced_system_monitor():
    anomaly_detector = AdvancedAnomalyDetector()
    
    while True:
        try:
            # Collect comprehensive metrics
            metrics = SystemFeatureExtractor.get_comprehensive_system_metrics()
            critical_procs = SystemFeatureExtractor.check_critical_processes()
            open_ports = NetworkSecurityAnalyzer.scan_open_ports()
            suspicious_connections = NetworkSecurityAnalyzer.analyze_network_connections()

            # Display current system metrics
            metrics_table = tabulate(
                metrics.items(), 
                headers=['Metric', 'Value'], 
                tablefmt='grid'
            )
            user_output_queue.add_message(f"Current System Metrics:\n{metrics_table}")

            # Prepare data for anomaly detection
            feature_vector = list(metrics.values())
            anomaly_detector.historical_data.append(feature_vector)
            
            # Limit historical data
            if len(anomaly_detector.historical_data) > ThreatDetectionConfig.MAX_HISTORICAL_DATA:
                anomaly_detector.historical_data.pop(0)

            # Periodically retrain model
            if len(anomaly_detector.historical_data) % 100 == 0:
                prepared_data = anomaly_detector.prepare_data()
                if prepared_data is not None:
                    anomaly_detector.train_model(prepared_data)

            # Anomaly Detection
            is_anomaly = anomaly_detector.detect_anomalies(feature_vector)
            
            if is_anomaly or critical_procs or open_ports or suspicious_connections:
                threat_details = {
                    'Timestamp': datetime.now().isoformat(),
                    'Metrics': metrics,
                    'Critical Processes': critical_procs,
                    'Open Ports': open_ports,
                    'Suspicious Connections': str(suspicious_connections)
                }
                send_threat_alert(threat_details)

            time.sleep(ThreatDetectionConfig.MONITORING_INTERVAL)

        except Exception as e:
            user_output_queue.add_message(f"Monitoring error: {e}", 'warning')
            time.sleep(ThreatDetectionConfig.MONITORING_INTERVAL)

def main():
    print(colorama.Fore.CYAN + "🔒 Advanced Real-Time Threat Detection System")
    print(colorama.Fore.GREEN + "Initializing monitoring components...")
    
    # Start message display thread
    display_thread = threading.Thread(target=user_output_queue.display_messages, daemon=True)
    display_thread.start()
    
    # Start monitoring in a separate process
    monitor_process = multiprocessing.Process(target=advanced_system_monitor)
    monitor_process.start()
    
    try:
        # Wait for the monitoring process
        monitor_process.join()
    except KeyboardInterrupt:
        print(colorama.Fore.YELLOW + "\n🛑 Threat Detection System Stopped.")
        user_output_queue.stop()
        monitor_process.terminate()
        sys.exit(0)

if __name__ == "__main__":
    # Install required packages if not already installed
    try:
        import colorama
        import tabulate
    except ImportError:
        print("Installing required packages...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'colorama', 'tabulate'])
    
    main()
