import sys
import os
import threading
import time
from datetime import datetime
from collections import deque
import numpy as np

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QTableWidget, QTableWidgetItem, QTextEdit, 
                             QComboBox, QLineEdit, QLabel, QSplitter, QTabWidget,
                             QProgressBar, QGroupBox, QCheckBox, QSpinBox, QFileDialog,
                             QMessageBox, QHeaderView, QTreeWidget, QTreeWidgetItem)
from PyQt5.QtCore import QTimer, Qt, pyqtSignal, QObject
from PyQt5.QtGui import QFont, QColor, QBrush

from packet_sniffer import PacketSniffer, get_network_interfaces

# Import your trained model
try:
    sys.path.append('../scripts')
    from hybrid_model import MemoryEfficientHybridDLMLModel
    MODEL_LOADED = True
except ImportError as e:
    print(f"Model import warning: {e}")
    MODEL_LOADED = False

class PacketSignal(QObject):
    packet_received = pyqtSignal(dict)
    stats_updated = pyqtSignal(dict)
    attack_detected = pyqtSignal(dict)  # New signal for attacks

class PacketSnifferGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.sniffer = None
        self.ids_model = None
        self.signal = PacketSignal()
        self.setup_ui()
        self.setup_sniffer()
        self.load_ids_model()
        
    def load_ids_model(self):
        """Load the trained hybrid IDS model"""
        if not MODEL_LOADED:
            self.statusBar().showMessage("IDS: Model not available - running in sniffer mode only")
            return
            
        try:
            model_path = "../models/hybrid_dl_ml_model.pkl"
            if os.path.exists(model_path):
                self.ids_model = MemoryEfficientHybridDLMLModel.load(model_path)
                self.statusBar().showMessage("IDS: Hybrid model loaded successfully - Real-time protection ENABLED")
                print("✅ IDS Model loaded successfully!")
            else:
                self.statusBar().showMessage("IDS: Model file not found - running in sniffer mode")
        except Exception as e:
            print(f"❌ Failed to load IDS model: {e}")
            self.statusBar().showMessage("IDS: Model loading failed - running in sniffer mode")
    
    def setup_ui(self):
        """Setup the main GUI"""
        self.setWindowTitle("Advanced Packet Sniffer with IDS v2.0")
        self.setGeometry(100, 100, 1600, 1000)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Control panel
        self.setup_control_panel(layout)
        
        # Main content area
        splitter = QSplitter(Qt.Vertical)
        layout.addWidget(splitter)
        
        # Packet table
        self.setup_packet_table(splitter)
        
        # Details area
        self.setup_details_area(splitter)
        
        # Set splitter proportions
        splitter.setSizes([500, 400])
        
        # Status bar
        self.setup_status_bar()
        
    def setup_control_panel(self, layout):
        """Setup the control panel with IDS options"""
        control_group = QGroupBox("Capture Controls & IDS Settings")
        control_layout = QVBoxLayout(control_group)
        
        # First row: Basic controls
        basic_layout = QHBoxLayout()
        
        # Interface selection
        basic_layout.addWidget(QLabel("Interface:"))
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(get_network_interfaces())
        self.interface_combo.setMinimumWidth(150)
        basic_layout.addWidget(self.interface_combo)
        
        # Filter
        basic_layout.addWidget(QLabel("Filter:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("e.g., tcp, udp, port 80, host 192.168.1.1")
        self.filter_edit.setMinimumWidth(200)
        basic_layout.addWidget(self.filter_edit)
        
        # Packet count
        basic_layout.addWidget(QLabel("Count:"))
        self.packet_count = QSpinBox()
        self.packet_count.setRange(0, 100000)
        self.packet_count.setValue(0)
        self.packet_count.setSpecialValueText("Unlimited")
        self.packet_count.setMinimumWidth(80)
        basic_layout.addWidget(self.packet_count)
        
        basic_layout.addStretch()
        
        # Second row: IDS controls
        ids_layout = QHBoxLayout()
        
        # IDS toggle
        self.ids_enabled = QCheckBox("Enable IDS Protection")
        self.ids_enabled.setChecked(True)
        self.ids_enabled.setEnabled(MODEL_LOADED)
        ids_layout.addWidget(self.ids_enabled)
        
        # Attack threshold
        ids_layout.addWidget(QLabel("Alert Threshold:"))
        self.threshold_combo = QComboBox()
        self.threshold_combo.addItems(["All Traffic", "Suspicious Only", "Attacks Only"])
        self.threshold_combo.setCurrentIndex(1)
        ids_layout.addWidget(self.threshold_combo)
        
        # Auto-block (future feature)
        self.auto_block = QCheckBox("Auto-block detected attacks")
        self.auto_block.setChecked(False)
        ids_layout.addWidget(self.auto_block)
        
        ids_layout.addStretch()
        
        # Buttons
        self.start_btn = QPushButton("Start Capture")
        self.start_btn.clicked.connect(self.start_capture)
        self.start_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }")
        ids_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Stop Capture")
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("QPushButton { background-color: #f44336; color: white; }")
        ids_layout.addWidget(self.stop_btn)
        
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.clear_packets)
        ids_layout.addWidget(self.clear_btn)
        
        self.save_btn = QPushButton("Save Packets")
        self.save_btn.clicked.connect(self.save_packets)
        ids_layout.addWidget(self.save_btn)
        
        control_layout.addLayout(basic_layout)
        control_layout.addLayout(ids_layout)
        layout.addWidget(control_group)
        
    def setup_packet_table(self, splitter):
        """Setup the packet table with IDS columns"""
        table_widget = QWidget()
        table_layout = QVBoxLayout(table_widget)
        
        # Statistics with IDS alerts
        stats_layout = QHBoxLayout()
        self.packet_count_label = QLabel("Packets: 0")
        self.attack_count_label = QLabel("Attacks: 0")
        self.protocol_label = QLabel("Protocols: -")
        self.duration_label = QLabel("Duration: 00:00:00")
        self.rate_label = QLabel("Rate: 0 pkt/s")
        self.ids_status_label = QLabel("IDS: Ready")
        
        # Style attack count
        self.attack_count_label.setStyleSheet("QLabel { color: red; font-weight: bold; }")
        self.ids_status_label.setStyleSheet("QLabel { color: green; font-weight: bold; }")
        
        stats_layout.addWidget(self.packet_count_label)
        stats_layout.addWidget(self.attack_count_label)
        stats_layout.addWidget(self.protocol_label)
        stats_layout.addWidget(self.duration_label)
        stats_layout.addWidget(self.rate_label)
        stats_layout.addWidget(self.ids_status_label)
        stats_layout.addStretch()
        
        table_layout.addLayout(stats_layout)
        
        # Packet table with IDS column
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(8)  # Added IDS column
        self.packet_table.setHorizontalHeaderLabels([
            "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info", "Threat"
        ])
        
        # Set column widths
        header = self.packet_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # No.
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Time
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Source
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Destination
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Protocol
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Length
        header.setSectionResizeMode(6, QHeaderView.Stretch)          # Info
        header.setSectionResizeMode(7, QHeaderView.ResizeToContents) # Threat
        
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.packet_table.clicked.connect(self.show_packet_details)
        table_layout.addWidget(self.packet_table)
        
        splitter.addWidget(table_widget)
        
    def setup_details_area(self, splitter):
        """Setup the packet details area with IDS analysis"""
        tabs = QTabWidget()
        
        # Hex dump tab
        self.hex_text = QTextEdit()
        self.hex_text.setFont(QFont("Courier", 10))
        self.hex_text.setReadOnly(True)
        tabs.addTab(self.hex_text, "Hex Dump")
        
        # Details tab
        self.details_tree = QTreeWidget()
        self.details_tree.setHeaderLabels(["Field", "Value"])
        tabs.addTab(self.details_tree, "Packet Details")
        
        # IDS Analysis tab
        self.ids_analysis_text = QTextEdit()
        self.ids_analysis_text.setReadOnly(True)
        self.ids_analysis_text.setFont(QFont("Arial", 10))
        tabs.addTab(self.ids_analysis_text, "IDS Analysis")
        
        # Statistics tab
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        tabs.addTab(self.stats_text, "Statistics")
        
        splitter.addWidget(tabs)
        
    def setup_status_bar(self):
        """Setup the status bar"""
        self.statusBar().showMessage("Ready to start packet capture with IDS protection")
        self.attack_counter = 0
        
    def setup_sniffer(self):
        """Setup the packet sniffer"""
        self.sniffer = PacketSniffer()
        self.sniffer.add_packet_callback(self.on_packet_received)
        
        # Connect signals
        self.signal.packet_received.connect(self.add_packet_to_table)
        self.signal.stats_updated.connect(self.update_statistics)
        self.signal.attack_detected.connect(self.on_attack_detected)
        
        # Setup update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_stats_display)
        self.update_timer.start(1000)  # Update every second
        
        self.packet_counter = 0
        self.last_packet_count = 0
        self.start_time = None
        
    def extract_features_from_packet(self, packet):
        """Extract features from packet for IDS model prediction"""
        try:
            # This should match the features used during training
            features = np.zeros(46)  # Your 46 features
            
            # Map packet info to features (you'll need to customize this based on your training)
            # This is a simplified example - you need to match your actual feature extraction
            if 'length' in packet:
                features[0] = packet['length']
            if 'protocol' in packet:
                # Convert protocol to numeric (you had Protocol Type in features)
                protocol_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'ARP': -1}
                features[2] = protocol_map.get(packet['protocol'], 0)
            
            # Add more feature extraction based on your training data structure
            # You need to replicate exactly how you created features during training
            
            return features
            
        except Exception as e:
            print(f"Feature extraction error: {e}")
            return None
    
    def analyze_packet_with_ids(self, packet):
        """Analyze packet using the trained IDS model"""
        if not self.ids_model or not self.ids_enabled.isChecked():
            return "Unknown"
            
        try:
            features = self.extract_features_from_packet(packet)
            if features is not None:
                # Reshape for model prediction
                features = features.reshape(1, -1)
                
                # Make prediction
                prediction = self.ids_model.predict(features)[0]
                
                return prediction
            else:
                return "Feature Error"
                
        except Exception as e:
            print(f"IDS prediction error: {e}")
            return "Prediction Error"
    
    def on_packet_received(self, packet):
        """Called when a new packet is received"""
        # Add IDS analysis
        if self.ids_model and self.ids_enabled.isChecked():
            threat_level = self.analyze_packet_with_ids(packet)
            packet['threat_level'] = threat_level
            packet['is_attack'] = threat_level != 'Benign'
            
            # Emit attack signal if detected
            if packet['is_attack']:
                self.signal.attack_detected.emit(packet)
        
        self.signal.packet_received.emit(packet)
    
    def on_attack_detected(self, packet):
        """Handle detected attacks"""
        self.attack_counter += 1
        self.attack_count_label.setText(f"Attacks: {self.attack_counter}")
        
        # Show alert for high-priority attacks
        if packet['threat_level'] in ['DDoS', 'DoS']:
            self.show_attack_alert(packet)
    
    def show_attack_alert(self, packet):
        """Show popup alert for serious attacks"""
        alert_msg = f"""
        🚨 SECURITY ALERT 🚨
        
        Attack Type: {packet['threat_level']}
        Source: {packet.get('source', 'Unknown')}
        Destination: {packet.get('destination', 'Unknown')}
        Time: {packet.get('time_str', 'Unknown')}
        Protocol: {packet.get('protocol', 'Unknown')}
        
        Immediate attention required!
        """
        
        QMessageBox.warning(self, "🚨 IDS Alert", alert_msg)
        
        # Update IDS status
        self.ids_status_label.setText("IDS: ATTACK DETECTED!")
        self.ids_status_label.setStyleSheet("QLabel { color: red; font-weight: bold; }")
        
        # Reset status after 5 seconds
        QTimer.singleShot(5000, self.reset_ids_status)
    
    def reset_ids_status(self):
        """Reset IDS status to normal"""
        self.ids_status_label.setText("IDS: Monitoring")
        self.ids_status_label.setStyleSheet("QLabel { color: green; font-weight: bold; }")
    
    def add_packet_to_table(self, packet):
        """Add packet to the table with threat coloring"""
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        
        # Packet number
        self.packet_counter += 1
        self.packet_table.setItem(row, 0, QTableWidgetItem(str(self.packet_counter)))
        
        # Time
        self.packet_table.setItem(row, 1, QTableWidgetItem(packet['time_str']))
        
        # Source
        self.packet_table.setItem(row, 2, QTableWidgetItem(packet['source']))
        
        # Destination
        self.packet_table.setItem(row, 3, QTableWidgetItem(packet['destination']))
        
        # Protocol
        protocol_item = QTableWidgetItem(packet['protocol'])
        self.color_protocol_item(protocol_item, packet['protocol'])
        self.packet_table.setItem(row, 4, protocol_item)
        
        # Length
        self.packet_table.setItem(row, 5, QTableWidgetItem(str(packet['length'])))
        
        # Info
        self.packet_table.setItem(row, 6, QTableWidgetItem(packet['info']))
        
        # Threat level (IDS column)
        threat_level = packet.get('threat_level', 'Unknown')
        threat_item = QTableWidgetItem(threat_level)
        self.color_threat_item(threat_item, threat_level)
        self.packet_table.setItem(row, 7, threat_item)
        
        # Color entire row if it's an attack
        if packet.get('is_attack', False):
            self.color_attack_row(row)
        
        # Auto-scroll to bottom
        self.packet_table.scrollToBottom()
        
    def color_protocol_item(self, item, protocol):
        """Color code protocol items"""
        colors = {
            'TCP': QColor(144, 238, 144),  # Light green
            'UDP': QColor(135, 206, 250),  # Light sky blue
            'ICMP': QColor(255, 182, 193), # Light pink
            'ARP': QColor(255, 215, 0),    # Gold
        }
        
        if protocol in colors:
            item.setBackground(colors[protocol])
            
    def color_threat_item(self, item, threat_level):
        """Color code threat levels"""
        colors = {
            'Benign': QColor(144, 238, 144),    # Green
            'DDoS': QColor(255, 0, 0),          # Red
            'DoS': QColor(255, 69, 0),          # Orange-red
            'Mirai': QColor(255, 140, 0),       # Dark orange
            'Recon': QColor(255, 215, 0),       # Yellow
            'BruteForce': QColor(255, 165, 0),  # Orange
            'Web': QColor(218, 112, 214),       # Orchid
            'Spoofing': QColor(138, 43, 226),   # Blue violet
        }
        
        if threat_level in colors:
            item.setBackground(colors[threat_level])
            item.setForeground(QBrush(QColor(0, 0, 0)))  # Black text
            
    def color_attack_row(self, row):
        """Color entire row for attacks"""
        for col in range(self.packet_table.columnCount()):
            item = self.packet_table.item(row, col)
            if item:
                item.setBackground(QColor(255, 200, 200))  # Light red background
            
    def show_packet_details(self, index):
        """Show details of selected packet with IDS analysis"""
        row = index.row()
        if row < 0:
            return
            
        # Get the packet from sniffer
        packets = self.sniffer.get_recent_packets()
        if row < len(packets):
            packet = packets[row]
            self.display_packet_details(packet)
            self.display_ids_analysis(packet)
            
    def display_packet_details(self, packet):
        """Display detailed packet information"""
        # Hex dump
        self.hex_text.setText(packet.get('hex_data', ''))
        
        # Detailed tree view
        self.details_tree.clear()
        
        # Basic info
        basic_info = QTreeWidgetItem(self.details_tree, ["Basic Information", ""])
        QTreeWidgetItem(basic_info, ["Timestamp", packet['time_str']])
        QTreeWidgetItem(basic_info, ["Source", packet['source']])
        QTreeWidgetItem(basic_info, ["Destination", packet['destination']])
        QTreeWidgetItem(basic_info, ["Protocol", packet['protocol']])
        QTreeWidgetItem(basic_info, ["Length", str(packet['length'])])
        
        # IDS Analysis if available
        if 'threat_level' in packet:
            ids_info = QTreeWidgetItem(self.details_tree, ["IDS Analysis", ""])
            QTreeWidgetItem(ids_info, ["Threat Level", packet['threat_level']])
            QTreeWidgetItem(ids_info, ["Classification", "Attack" if packet.get('is_attack', False) else "Benign"])
        
        # MAC addresses if available
        if 'src_mac' in packet:
            mac_info = QTreeWidgetItem(self.details_tree, ["Ethernet", ""])
            QTreeWidgetItem(mac_info, ["Source MAC", packet['src_mac']])
            QTreeWidgetItem(mac_info, ["Destination MAC", packet['dst_mac']])
        
        # Port information if available
        if 'sport' in packet:
            port_info = QTreeWidgetItem(self.details_tree, ["Ports", ""])
            QTreeWidgetItem(port_info, ["Source Port", str(packet['sport'])])
            QTreeWidgetItem(port_info, ["Destination Port", str(packet['dport'])])
        
        # Expand all items
        self.details_tree.expandAll()
    
    def display_ids_analysis(self, packet):
        """Display IDS analysis in dedicated tab"""
        analysis_text = "🔍 IDS Threat Analysis\n"
        analysis_text += "=" * 50 + "\n\n"
        
        if 'threat_level' in packet:
            threat = packet['threat_level']
            is_attack = packet.get('is_attack', False)
            
            analysis_text += f"Threat Classification: {threat}\n"
            analysis_text += f"Security Status: {'🚨 MALICIOUS' if is_attack else '✅ BENIGN'}\n\n"
            
            if is_attack:
                analysis_text += "🚨 SECURITY ALERT:\n"
                analysis_text += f"- Attack Type: {threat}\n"
                analysis_text += f"- Source: {packet.get('source', 'Unknown')}\n"
                analysis_text += f"- Destination: {packet.get('destination', 'Unknown')}\n"
                analysis_text += f"- Protocol: {packet.get('protocol', 'Unknown')}\n"
                analysis_text += f"- Packet Size: {packet.get('length', 'Unknown')} bytes\n\n"
                
                # Add recommendations based on attack type
                analysis_text += "🛡️ RECOMMENDED ACTIONS:\n"
                if threat in ['DDoS', 'DoS']:
                    analysis_text += "- Block source IP temporarily\n"
                    analysis_text += "- Increase network monitoring\n"
                    analysis_text += "- Check server load and resources\n"
                elif threat == 'BruteForce':
                    analysis_text += "- Review authentication logs\n"
                    analysis_text += "- Implement account lockout policies\n"
                    analysis_text += "- Check for compromised accounts\n"
                elif threat == 'Recon':
                    analysis_text += "- Monitor for further scanning activity\n"
                    analysis_text += "- Review firewall rules\n"
                    analysis_text += "- Check for vulnerability scans\n"
            else:
                analysis_text += "✅ This traffic appears to be normal and benign.\n"
                analysis_text += "No immediate security action required.\n"
        else:
            analysis_text += "IDS analysis not available for this packet.\n"
            analysis_text += "Make sure IDS protection is enabled.\n"
        
        self.ids_analysis_text.setText(analysis_text)
        
    # ... (keep the existing update_statistics, update_stats_display, 
    # start_capture, stop_capture, clear_packets, save_packets methods the same)
    
    def update_statistics(self, stats):
        """Update statistics display"""
        self.stats_text.clear()
        
        stats_text = f"Capture Statistics\n{'='*50}\n"
        stats_text += f"Total Packets: {stats['total_packets']}\n"
        stats_text += f"Detected Attacks: {self.attack_counter}\n"
        
        if 'duration' in stats:
            duration = stats['duration']
            stats_text += f"Duration: {duration}\n"
            
        stats_text += f"\nProtocol Distribution:\n"
        for protocol, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True):
            stats_text += f"  {protocol}: {count}\n"
            
        stats_text += f"\nTop Sources:\n"
        for source, count in sorted(stats['sources'].items(), key=lambda x: x[1], reverse=True)[:10]:
            stats_text += f"  {source}: {count}\n"
            
        stats_text += f"\nTop Destinations:\n"
        for dest, count in sorted(stats['destinations'].items(), key=lambda x: x[1], reverse=True)[:10]:
            stats_text += f"  {dest}: {count}\n"
            
        self.stats_text.setText(stats_text)
        
    def update_stats_display(self):
        """Update the statistics display in real-time"""
        if self.sniffer and self.sniffer.is_sniffing:
            stats = self.sniffer.get_statistics()
            
            # Update labels
            self.packet_count_label.setText(f"Packets: {stats['total_packets']}")
            self.attack_count_label.setText(f"Attacks: {self.attack_counter}")
            
            # Protocol distribution
            top_protocols = sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True)[:3]
            protocol_text = "Protocols: " + ", ".join([f"{p}({c})" for p, c in top_protocols])
            self.protocol_label.setText(protocol_text)
            
            # Duration
            if 'duration' in stats:
                duration = stats['duration']
                hours, remainder = divmod(duration.total_seconds(), 3600)
                minutes, seconds = divmod(remainder, 60)
                self.duration_label.setText(f"Duration: {int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}")
                
            # Packet rate
            current_count = stats['total_packets']
            rate = current_count - self.last_packet_count
            self.rate_label.setText(f"Rate: {rate} pkt/s")
            self.last_packet_count = current_count
            
            # Update detailed statistics
            self.signal.stats_updated.emit(stats)
            
    def start_capture(self):
        """Start packet capture"""
        try:
            interface = self.interface_combo.currentText()
            filter_str = self.filter_edit.text().strip() or None
            count = self.packet_count.value() or 0
            
            self.sniffer.interface = interface
            if self.sniffer.start_sniffing(filter_str, count):
                self.start_btn.setEnabled(False)
                self.stop_btn.setEnabled(True)
                self.start_time = datetime.now()
                self.last_packet_count = 0
                self.attack_counter = 0  # Reset attack counter
                status_msg = f"Capturing on {interface}"
                if self.ids_model and self.ids_enabled.isChecked():
                    status_msg += " with IDS protection"
                self.statusBar().showMessage(status_msg)
            else:
                QMessageBox.warning(self, "Error", "Could not start capture. Another capture might be running.")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start capture: {str(e)}")
            
    def stop_capture(self):
        """Stop packet capture"""
        self.sniffer.stop_sniffing()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.statusBar().showMessage("Capture stopped")
        
    def clear_packets(self):
        """Clear all captured packets"""
        self.sniffer.clear_packets()
        self.packet_table.setRowCount(0)
        self.packet_counter = 0
        self.attack_counter = 0
        self.attack_count_label.setText("Attacks: 0")
        self.hex_text.clear()
        self.details_tree.clear()
        self.ids_analysis_text.clear()
        self.stats_text.clear()
        self.statusBar().showMessage("Packets cleared")
        
    def save_packets(self):
        """Save captured packets to file"""
        if not self.sniffer.packets:
            QMessageBox.information(self, "Save Packets", "No packets to save.")
            return
            
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Packets", f"packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "CSV Files (*.csv);;PCAP Files (*.pcap)"
        )
        
        if filename:
            if filename.endswith('.csv'):
                success = self.sniffer.save_packets_to_file(filename, 'csv')
            else:
                success = self.sniffer.save_packets_to_file(filename, 'pcap')
                
            if success:
                QMessageBox.information(self, "Save Packets", f"Packets saved to {filename}")
            else:
                QMessageBox.warning(self, "Save Packets", "Failed to save packets.")
                
    def closeEvent(self, event):
        """Handle application closure"""
        if self.sniffer and self.sniffer.is_sniffing:
            self.sniffer.stop_sniffing()
        event.accept()

def main():
    app = QApplication(sys.argv)
    
    # Check if running as administrator (required for packet capture on Windows)
    try:
        import ctypes
        if os.name == 'nt' and ctypes.windll.shell32.IsUserAnAdmin() == 0:
            QMessageBox.warning(None, "Admin Rights", 
                              "Packet capture may require administrator privileges on Windows.\n"
                              "Please run as Administrator for best results.")
    except:
        pass
    
    window = PacketSnifferGUI()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()