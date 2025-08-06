#!/usr/bin/env python3
"""
Network Intrusion Detection System (NIDS)
A comprehensive network-based intrusion detection system that monitors traffic,
detects suspicious activities, and provides real-time alerts and visualization.

Features:
- Real-time packet capture and analysis
- Rule-based detection engine
- Automated response mechanisms
- Web dashboard with visualizations
- Alert management and logging
- Statistical analysis and reporting

Requirements:
- Run with administrator/root privileges
- Install dependencies: pip install scapy flask plotly pandas
"""

import os
import re
import json
import time
import sqlite3
import threading
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from typing import Dict, List, Set, Optional, Tuple
import argparse
import logging


from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS


try:
    from flask import Flask, render_template_string, jsonify, request
    import plotly.graph_objs as go
    import plotly.utils
    import pandas as pd
    DASHBOARD_AVAILABLE = True
except ImportError:
    DASHBOARD_AVAILABLE = False
    print("Warning: Flask/Plotly not available. Dashboard disabled.")
    print("Install with: pip install flask plotly pandas")

@dataclass
class Alert:
    id: str
    timestamp: datetime
    severity: str
    category: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    description: str
    packet_data: str
    rule_triggered: str
    response_action: str = "LOG"

class DetectionRule:
    def __init__(self, name: str, pattern: str, severity: str, category: str, 
                 description: str, response: str = "LOG"):
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.severity = severity
        self.category = category
        self.description = description
        self.response = response
        self.trigger_count = 0
        self.last_triggered = None

class NetworkIDS:
    def __init__(self, interface=None, log_file="nids.log"):
        self.interface = interface
        self.log_file = log_file
        self.alerts = deque(maxlen=10000)  
        self.active_connections = {}
        self.packet_stats = defaultdict(int)
        self.traffic_stats = defaultdict(lambda: defaultdict(int))
        self.blocked_ips = set()
        self.detection_rules = []
        self.running = False
        
        
        self.connection_tracking = defaultdict(lambda: defaultdict(int))
        self.packet_timing = defaultdict(deque)
        
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        
        self.init_database()
        
        
        self.load_default_rules()
        
        
        if DASHBOARD_AVAILABLE:
            self.setup_dashboard()

    def init_database(self):
        """Initialize SQLite database for storing alerts and statistics"""
        self.conn = sqlite3.connect('nids_data.db', check_same_thread=False)
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                severity TEXT,
                category TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT,
                description TEXT,
                rule_triggered TEXT,
                response_action TEXT
            )
        ''')
        
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS traffic_stats (
                timestamp TEXT,
                protocol TEXT,
                packet_count INTEGER,
                byte_count INTEGER
            )
        ''')
        self.conn.commit()

    def load_default_rules(self):
        """Load default intrusion detection rules"""
        default_rules = [
            
            DetectionRule(
                "Port Scan Detection",
                r".*",  
                "HIGH",
                "Reconnaissance",
                "Multiple port connection attempts detected",
                "BLOCK"
            ),
            
            
            DetectionRule(
                "SSH Brute Force",
                r"ssh.*failed|authentication failure",
                "HIGH",
                "Brute Force",
                "Multiple SSH login failures detected",
                "BLOCK"
            ),
            
            
            DetectionRule(
                "DDoS Attack",
                r".*",  
                "CRITICAL",
                "DDoS",
                "Distributed Denial of Service attack detected",
                "BLOCK"
            ),
            
            
            DetectionRule(
                "Suspicious DNS Query",
                r"(\.tk|\.ml|\.ga|\.cf)$",
                "MEDIUM",
                "Malware",
                "DNS query to suspicious TLD",
                "LOG"
            ),
            
            
            DetectionRule(
                "Large Data Transfer",
                r".*",  
                "MEDIUM",
                "Data Exfiltration",
                "Unusually large data transfer detected",
                "LOG"
            ),
            
            
            DetectionRule(
                "HTTP on Non-Standard Port",
                r"GET|POST|PUT|DELETE",
                "LOW",
                "Protocol Anomaly",
                "HTTP traffic on non-standard port",
                "LOG"
            ),
            
            
            DetectionRule(
                "ICMP Sweep",
                r".*",  
                "MEDIUM",
                "Reconnaissance",
                "ICMP sweep/ping scan detected",
                "LOG"
            ),
            
            
            DetectionRule(
                "SQL Injection Attempt",
                r"(union|select|insert|delete|drop|exec|script)",
                "HIGH",
                "Web Attack",
                "Potential SQL injection in HTTP traffic",
                "BLOCK"
            ),
            
            DetectionRule(
                "XSS Attempt",
                r"(<script|javascript:|vbscript:|onload=|onerror=)",
                "HIGH",
                "Web Attack",
                "Potential XSS attack in HTTP traffic",
                "BLOCK"
            ),
            
            
            DetectionRule(
                "Password in Clear Text",
                r"password=|pwd=|pass=",
                "MEDIUM",
                "Credential Exposure",
                "Plain text password transmission detected",
                "LOG"
            )
        ]
        
        self.detection_rules = default_rules
        self.logger.info(f"Loaded {len(default_rules)} default detection rules")

    def start_monitoring(self, packet_count=0):
        """Start network traffic monitoring"""
        self.running = True
        self.logger.info(f"Starting network monitoring on interface: {self.interface or 'default'}")
        
        try:
            
            capture_thread = threading.Thread(
                target=self._capture_packets, 
                args=(packet_count,)
            )
            capture_thread.daemon = True
            capture_thread.start()
            
            
            stats_thread = threading.Thread(target=self._collect_statistics)
            stats_thread.daemon = True
            stats_thread.start()
            
            
            if DASHBOARD_AVAILABLE:
                dashboard_thread = threading.Thread(target=self._run_dashboard)
                dashboard_thread.daemon = True
                dashboard_thread.start()
                print("Dashboard available at: http://localhost:5000")
            
            self.logger.info("Network IDS started successfully")
            
            
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.stop_monitoring()
                
        except Exception as e:
            self.logger.error(f"Error starting monitoring: {e}")

    def _capture_packets(self, packet_count):
        """Capture and analyze network packets"""
        try:
            sniff(
                iface=self.interface,
                prn=self.analyze_packet,
                count=packet_count,
                store=0
            )
        except Exception as e:
            self.logger.error(f"Packet capture error: {e}")

    def analyze_packet(self, packet):
        """Analyze individual packets for threats"""
        if not self.running:
            return
            
        try:
            
            self.packet_stats['total'] += 1
            
            
            packet_info = self._extract_packet_info(packet)
            if not packet_info:
                return
            
            
            self._update_traffic_stats(packet_info)
            
            
            self._run_detections(packet, packet_info)
            
        except Exception as e:
            self.logger.error(f"Packet analysis error: {e}")

    def _extract_packet_info(self, packet) -> Optional[Dict]:
        """Extract relevant information from packet"""
        info = {}
        
        try:
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                info.update({
                    'src_ip': ip_layer.src,
                    'dst_ip': ip_layer.dst,
                    'protocol': ip_layer.proto,
                    'packet_size': len(packet)
                })
                
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    info.update({
                        'src_port': tcp_layer.sport,
                        'dst_port': tcp_layer.dport,
                        'tcp_flags': tcp_layer.flags,
                        'protocol_name': 'TCP'
                    })
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    info.update({
                        'src_port': udp_layer.sport,
                        'dst_port': udp_layer.dport,
                        'protocol_name': 'UDP'
                    })
                elif packet.haslayer(ICMP):
                    info.update({
                        'src_port': 0,
                        'dst_port': 0,
                        'protocol_name': 'ICMP'
                    })
                
                
                if packet.haslayer(Raw):
                    try:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        info['payload'] = payload[:1000]  
                    except:
                        info['payload'] = ''
                
                return info
                
        except Exception as e:
            self.logger.debug(f"Packet extraction error: {e}")
            
        return None

    def _update_traffic_stats(self, packet_info):
        """Update traffic statistics"""
        current_time = datetime.now()
        protocol = packet_info.get('protocol_name', 'Unknown')
        
        
        minute_key = current_time.strftime('%Y-%m-%d %H:%M')
        self.traffic_stats[minute_key][protocol] += 1
        self.traffic_stats[minute_key]['total_bytes'] += packet_info.get('packet_size', 0)

    def _run_detections(self, packet, packet_info):
        """Run all detection algorithms"""
        
        self.detect_port_scan(packet_info)
        
        
        self.detect_ddos(packet_info)
        
        
        if packet_info.get('protocol_name') == 'ICMP':
            self.detect_icmp_sweep(packet_info)
        
        
        self.analyze_packet_size(packet_info)
        
        
        payload = packet_info.get('payload', '')
        if payload:
            self.analyze_payload(packet_info, payload)
        
        
        if packet.haslayer(DNS):
            self.analyze_dns_traffic(packet, packet_info)

    def detect_port_scan(self, packet_info):
        """Detect port scanning activities"""
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        dst_port = packet_info.get('dst_port')
        
        if not all([src_ip, dst_ip, dst_port]):
            return
        
        
        key = f"{src_ip}_{dst_ip}"
        current_time = time.time()
        
        
        if key not in self.connection_tracking:
            self.connection_tracking[key] = {'ports': set(), 'last_time': current_time}
        
        
        self.connection_tracking[key]['ports'].add(dst_port)
        self.connection_tracking[key]['last_time'] = current_time
        
        
        if len(self.connection_tracking[key]['ports']) > 10:
            if current_time - self.connection_tracking[key]['last_time'] < 60:
                self.create_alert(
                    "HIGH",
                    "Reconnaissance",
                    src_ip, dst_ip, 0, 0, "TCP",
                    f"Port scan detected: {len(self.connection_tracking[key]['ports'])} ports scanned",
                    "Port Scan Detection",
                    "BLOCK"
                )
                
                
                del self.connection_tracking[key]

    def detect_ddos(self, packet_info):
        """Detect DDoS attacks based on traffic volume"""
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        
        if not src_ip or not dst_ip:
            return
        
        current_time = time.time()
        
        
        if src_ip not in self.packet_timing:
            self.packet_timing[src_ip] = deque()
        
        
        self.packet_timing[src_ip].append(current_time)
        
        
        while (self.packet_timing[src_ip] and 
               current_time - self.packet_timing[src_ip][0] > 10):
            self.packet_timing[src_ip].popleft()
        
        
        if len(self.packet_timing[src_ip]) > 100:
            self.create_alert(
                "CRITICAL",
                "DDoS",
                src_ip, dst_ip, 0, 0, 
                packet_info.get('protocol_name', 'Unknown'),
                f"DDoS attack detected: {len(self.packet_timing[src_ip])} packets in 10 seconds",
                "DDoS Attack",
                "BLOCK"
            )
            
            
            self.blocked_ips.add(src_ip)
            self.logger.warning(f"IP {src_ip} blocked due to DDoS attack")

    def detect_icmp_sweep(self, packet_info):
        """Detect ICMP ping sweeps"""
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        
        if not src_ip or not dst_ip:
            return
        
        
        key = f"icmp_{src_ip}"
        current_time = time.time()
        
        if key not in self.connection_tracking:
            self.connection_tracking[key] = {'targets': set(), 'start_time': current_time}
        
        self.connection_tracking[key]['targets'].add(dst_ip)
        
        
        if len(self.connection_tracking[key]['targets']) > 20:
            if current_time - self.connection_tracking[key]['start_time'] < 30:
                self.create_alert(
                    "MEDIUM",
                    "Reconnaissance",
                    src_ip, "", 0, 0, "ICMP",
                    f"ICMP sweep detected: {len(self.connection_tracking[key]['targets'])} targets",
                    "ICMP Sweep",
                    "LOG"
                )

    def analyze_packet_size(self, packet_info):
        """Analyze packet sizes for potential data exfiltration"""
        packet_size = packet_info.get('packet_size', 0)
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        
        
        if packet_size > 1400:
            self.create_alert(
                "MEDIUM",
                "Data Exfiltration",
                src_ip, dst_ip, 
                packet_info.get('src_port', 0),
                packet_info.get('dst_port', 0),
                packet_info.get('protocol_name', 'Unknown'),
                f"Large packet detected: {packet_size} bytes",
                "Large Data Transfer",
                "LOG"
            )

    def analyze_payload(self, packet_info, payload):
        """Analyze packet payload for suspicious content"""
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        src_port = packet_info.get('src_port', 0)
        dst_port = packet_info.get('dst_port', 0)
        protocol = packet_info.get('protocol_name', 'Unknown')
        
        
        for rule in self.detection_rules:
            if rule.name in ["Port Scan Detection", "DDoS Attack", "ICMP Sweep", "Large Data Transfer"]:
                continue  
                
            if rule.pattern.search(payload):
                rule.trigger_count += 1
                rule.last_triggered = datetime.now()
                
                self.create_alert(
                    rule.severity,
                    rule.category,
                    src_ip, dst_ip, src_port, dst_port, protocol,
                    rule.description,
                    rule.name,
                    rule.response
                )

    def analyze_dns_traffic(self, packet, packet_info):
        """Analyze DNS traffic for suspicious domains"""
        try:
            dns_layer = packet[DNS]
            if dns_layer.qd:
                query_name = dns_layer.qd.qname.decode('utf-8', errors='ignore')
                
                
                for rule in self.detection_rules:
                    if rule.name == "Suspicious DNS Query":
                        if rule.pattern.search(query_name):
                            self.create_alert(
                                rule.severity,
                                rule.category,
                                packet_info.get('src_ip', ''),
                                packet_info.get('dst_ip', ''),
                                packet_info.get('src_port', 0),
                                packet_info.get('dst_port', 0),
                                "DNS",
                                f"Suspicious DNS query: {query_name}",
                                rule.name,
                                rule.response
                            )
        except Exception as e:
            self.logger.debug(f"DNS analysis error: {e}")

    def create_alert(self, severity, category, src_ip, dst_ip, src_port, dst_port, 
                    protocol, description, rule_name, response_action):
        """Create and process security alert"""
        alert_id = f"{int(time.time())}_{src_ip}_{dst_ip}"
        
        alert = Alert(
            id=alert_id,
            timestamp=datetime.now(),
            severity=severity,
            category=category,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol=protocol,
            description=description,
            packet_data="",
            rule_triggered=rule_name,
            response_action=response_action
        )
        
        
        self.alerts.append(alert)
        
        
        self._save_alert_to_db(alert)
        
        
        self.logger.warning(f"ALERT [{severity}] {category}: {description} "
                          f"({src_ip}:{src_port} -> {dst_ip}:{dst_port})")
        
    
        self.execute_response(alert)

    def _save_alert_to_db(self, alert):
        """Save alert to database"""
        try:
            self.conn.execute(
                '''INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (alert.id, alert.timestamp.isoformat(), alert.severity, alert.category,
                 alert.source_ip, alert.destination_ip, alert.source_port,
                 alert.destination_port, alert.protocol, alert.description,
                 alert.rule_triggered, alert.response_action)
            )
            self.conn.commit()
        except Exception as e:
            self.logger.error(f"Database save error: {e}")

    def execute_response(self, alert):
        """Execute automated response based on alert"""
        if alert.response_action == "BLOCK":
            self.block_ip(alert.source_ip)
        elif alert.response_action == "QUARANTINE":
            self.quarantine_connection(alert.source_ip, alert.destination_ip)
        

    def block_ip(self, ip_address):
        """Block IP address using iptables (Linux) or Windows Firewall"""
        if ip_address in self.blocked_ips:
            return  
        
        try:
            if os.name == 'posix':  
                subprocess.run([
                    'iptables', '-I', 'INPUT', '-s', ip_address, '-j', 'DROP'
                ], check=True, capture_output=True)
                self.logger.info(f"Blocked IP {ip_address} using iptables")
            elif os.name == 'nt':  
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name=NIDS_Block_{ip_address}', 'dir=in', 'action=block',
                    f'remoteip={ip_address}'
                ], check=True, capture_output=True)
                self.logger.info(f"Blocked IP {ip_address} using Windows Firewall")
            
            self.blocked_ips.add(ip_address)
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to block IP {ip_address}: {e}")
        except Exception as e:
            self.logger.error(f"Error blocking IP {ip_address}: {e}")

    def _collect_statistics(self):
        """Collect and store traffic statistics"""
        while self.running:
            try:
                time.sleep(60)  
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M')
                
                
                for protocol, count in self.packet_stats.items():
                    if count > 0:
                        self.conn.execute(
                            '''INSERT INTO traffic_stats VALUES (?, ?, ?, ?)''',
                            (current_time, protocol, count, 0)
                        )
                
                self.conn.commit()
                
                
                self.packet_stats.clear()
                
            except Exception as e:
                self.logger.error(f"Statistics collection error: {e}")

    def setup_dashboard(self):
        """Setup Flask web dashboard"""
        self.app = Flask(__name__)
        self.app.secret_key = 'nids_dashboard_key'
        
        @self.app.route('/')
        def dashboard():
            return render_template_string(DASHBOARD_HTML)
        
        @self.app.route('/api/alerts')
        def get_alerts():
            recent_alerts = list(self.alerts)[-50:]  # Last 50 alerts
            return jsonify([asdict(alert) for alert in recent_alerts])
        
        @self.app.route('/api/stats')
        def get_stats():
            stats = {
                'total_packets': sum(self.packet_stats.values()),
                'total_alerts': len(self.alerts),
                'blocked_ips': len(self.blocked_ips),
                'active_rules': len(self.detection_rules)
            }
            return jsonify(stats)
        
        @self.app.route('/api/traffic_chart')
        def traffic_chart():
            
            times = []
            tcp_counts = []
            udp_counts = []
            
            current_time = datetime.now()
            for i in range(10, 0, -1):
                time_key = (current_time - timedelta(minutes=i)).strftime('%Y-%m-%d %H:%M')
                times.append(time_key)
                tcp_counts.append(self.traffic_stats[time_key].get('TCP', 0))
                udp_counts.append(self.traffic_stats[time_key].get('UDP', 0))
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=times, y=tcp_counts, name='TCP', line=dict(color='blue')))
            fig.add_trace(go.Scatter(x=times, y=udp_counts, name='UDP', line=dict(color='red')))
            fig.update_layout(title='Network Traffic Over Time', xaxis_title='Time', yaxis_title='Packet Count')
            
            return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    def _run_dashboard(self):
        """Run Flask dashboard"""
        try:
            self.app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
        except Exception as e:
            self.logger.error(f"Dashboard error: {e}")

    def stop_monitoring(self):
        """Stop network monitoring"""
        self.running = False
        self.logger.info("Network IDS stopped")
        
        
        self.generate_report()

    def generate_report(self):
        """Generate comprehensive security report"""
        report_file = f"nids_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report_data = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'total_alerts': len(self.alerts),
                'blocked_ips': list(self.blocked_ips),
                'detection_rules': len(self.detection_rules)
            },
            'alert_summary': self._get_alert_summary(),
            'recent_alerts': [asdict(alert) for alert in list(self.alerts)[-100:]],
            'traffic_statistics': dict(self.packet_stats),
            'rule_statistics': [
                {
                    'name': rule.name,
                    'trigger_count': rule.trigger_count,
                    'last_triggered': rule.last_triggered.isoformat() if rule.last_triggered else None
                }
                for rule in self.detection_rules
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        self.logger.info(f"Security report saved to: {report_file}")
        return report_file

    def _get_alert_summary(self):
        """Get summary of alerts by severity and category"""
        summary = defaultdict(lambda: defaultdict(int))
        
        for alert in self.alerts:
            summary[alert.severity][alert.category] += 1
        
        return dict(summary)


DASHBOARD_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Network IDS Dashboard</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #1a1a1a; color: #ffffff; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                 color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 20px; }
        .stat-card { background-color: #2d2d2d; padding: 20px; border-radius: 10px; text-align: center; border: 1px solid #444; }
        .stat-number { font-size: 2em; font-weight: bold; color: #4CAF50; }
        .stat-label { color: #cccccc; margin-top: 5px; }
        .alerts-section { background-color: #2d2d2d; padding: 20px; border-radius: 10px; border: 1px solid #444; }
        .alert-item { border-left: 4px solid #ff6b6b; padding: 10px; margin: 10px 0; background-color: #3d3d3d; border-radius: 5px; }
        .alert-critical { border-left-color: #ff6b6b; }
        .alert-high { border-left-color: #ffa726; }
        .alert-medium { border-left-color: #ffeb3b; }
        .alert-low { border-left-color: #4caf50; }
        .chart-container { background-color: #2d2d2d; padding: 20px; border-radius: 10px; margin: 20px 0; border: 1px solid #444; }
        .refresh-btn { background-color: #4CAF50; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
        .refresh-btn:hover { background-color: #45a049; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Network Intrusion Detection System</h1>
        <p>Real-time Network Security Monitoring Dashboard</p>
        <button class="refresh-btn" onclick="refreshData()">🔄 Refresh Data</button>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-number" id="total-packets">0</div>
            <div class="stat-label">Total Packets</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" id="total-alerts">0</div>
            <div class="stat-label">Security Alerts</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" id="blocked-ips">0</div>
            <div class="stat-label">Blocked IPs</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" id="active-rules">0</div>
            <div class="stat-label">Active Rules</div>
        </div>
    </div>

    <div class="chart-container">
        <h3>📊 Network Traffic Analysis</h3>
        <div id="traffic-chart"></div>
    </div>

    <div class="alerts-section">
        <h3>🚨 Recent Security Alerts</h3>
        <div id="alerts-container">
            <p>Loading alerts...</p>
        </div>
    </div>

    <script>
        function refreshData() {
            loadStats();
            loadAlerts();
            loadTrafficChart();
        }

        function loadStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('total-packets').textContent = data.total_packets;
                    document.getElementById('total-alerts').textContent = data.total_alerts;
                    document.getElementById('blocked-ips').textContent = data.blocked_ips;
                    document.getElementById('active-rules').textContent = data.active_rules;
                });
        }

        function loadAlerts() {
            fetch('/api/alerts')
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('alerts-container');
                    if (data.length === 0) {
                        container.innerHTML = '<p>No alerts detected.</p>';
                        return;
                    }
                    
                    container.innerHTML = data.map(alert => `
                        <div class="alert-item alert-${alert.severity.toLowerCase()}">
                            <strong>[${alert.severity}] ${alert.category}</strong><br>
                            <small>${new Date(alert.timestamp).toLocaleString()}</small><br>
                            ${alert.description}<br>
                            <em>${alert.source_ip}:${alert.source_port} → ${alert.destination_ip}:${alert.destination_port} (${alert.protocol})</em>
                        </div>
                    `).join('');
                });
        }

        function loadTrafficChart() {
            fetch('/api/traffic_chart')
                .then(response => response.json())
                .then(data => {
                    Plotly.newPlot('traffic-chart', data.data, data.layout, {responsive: true});
                });
        }

        // Load initial data
        refreshData();
        
        // Auto-refresh every 30 seconds
        setInterval(refreshData, 30000);
    </script>
</body>
</html>
'''


def main():
    parser = argparse.ArgumentParser(description='Network Intrusion Detection System')
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    parser.add_argument('-c', '--count', type=int, default=0, 
                       help='Number of packets to capture (0 = unlimited)')
    parser.add_argument('--log-file', default='nids.log', 
                       help='Log file path')
    parser.add_argument('--no-dashboard', action='store_true',
                       help='Disable web dashboard')
    parser.add_argument('--config', help='Configuration file path')
    
    args = parser.parse_args()
    
    print("🛡️  Network Intrusion Detection System")
    print("=" * 50)
    
    
    if os.name == 'posix' and os.getuid() != 0:
        print("⚠️  Warning: Root privileges recommended for full functionality")
        print("   Try running with: sudo python3 network_ids.py")
    
    if not DASHBOARD_AVAILABLE and not args.no_dashboard:
        print("⚠️  Dashboard dependencies not installed")
        print("   Install with: pip install flask plotly pandas")
    
    
    try:
        ids = NetworkIDS(
            interface=args.interface,
            log_file=args.log_file
        )
        
        print(f"🔍 Monitoring interface: {args.interface or 'default'}")
        print(f"📝 Log file: {args.log_file}")
        print(f"🔧 Detection rules loaded: {len(ids.detection_rules)}")
        
        if DASHBOARD_AVAILABLE and not args.no_dashboard:
            print("🌐 Web dashboard will be available at: http://localhost:5000")
        
        print("\n🚀 Starting network monitoring...")
        print("   Press Ctrl+C to stop")
        
        ids.start_monitoring(args.count)
        
    except KeyboardInterrupt:
        print("\n🛑 Stopping Network IDS...")
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())