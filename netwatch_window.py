
# opsec_gui_watcher.py (V2 - with Most Used Ports/IPs and Debugging)

import sys
import time
import queue
import ollama
import collections

from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw
try:
    from scapy.layers.http import HTTP, HTTPS
except ImportError:
    print("Warning: scapy.layers.http could not be imported. HTTP/HTTPS traffic parsing will be basic.")
    HTTP = None
    HTTPS = None

import logging
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QPushButton, QTextEdit, QLineEdit, QLabel, QSpinBox, QMessageBox, QComboBox, QGroupBox
)
from PyQt6.QtCore import QThread, pyqtSignal, pyqtSlot, Qt, QTimer

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# --- Network Sniffing and LLM Processing Worker ---
class NetworkSnifferWorker(QThread):
    new_event_signal = pyqtSignal(str)
    llm_analysis_signal = pyqtSignal(str)
    most_used_signal = pyqtSignal(list, list)
    error_signal = pyqtSignal(str)
    status_signal = pyqtSignal(str)

    def __init__(self, interface, llm_model, batch_duration, max_events, parent=None):
        super().__init__(parent)
        self.interface = interface
        self.llm_model = llm_model
        self.batch_duration = batch_duration
        self.max_events = max_events

        self._running = True
        self.network_events_queue = queue.Queue()
        self.processed_events = []

        self.ip_counts = collections.Counter()
        self.port_counts = collections.Counter()
        self.last_stats_update_time = time.time()
        self.STATS_UPDATE_INTERVAL = 5 # Update stats display every 5 seconds

        self.last_batch_time = time.time()
        self.packet_count = 0 # For debugging print frequency

    def stop(self):
        self._running = False

    def process_packet(self, packet):
        if not self._running:
            return

        self.packet_count += 1 # Increment packet count
        event_summary = None

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            self.ip_counts[src_ip] += 1
            self.ip_counts[dst_ip] += 1

            # Debug print for IP/Port counts (don't print every packet, it's too much)
            # if self.packet_count % 50 == 0: # Print every 50 packets
            #     print(f"DEBUG: Packet {self.packet_count} - IPs: {self.ip_counts.most_common(3)}")
            #     print(f"DEBUG: Packet {self.packet_count} - Ports: {self.port_counts.most_common(3)}")

            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                query_name = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                event_summary = f"DNS Query: {src_ip} queried for '{query_name}' from DNS server {dst_ip}"

            elif TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                self.port_counts[src_port] += 1
                self.port_counts[dst_port] += 1

                if dst_port == 80 or src_port == 80:
                    if Raw in packet:
                        try:
                            payload = packet[Raw].load.decode('utf-8', errors='ignore')
                            if HTTP and packet.haslayer(HTTP.HTTPRequest):
                                http_method = packet[HTTP.HTTPRequest].Method.decode('utf-8', errors='ignore')
                                http_host = packet[HTTP.HTTPRequest].Host.decode('utf-8', errors='ignore')
                                http_path = packet[HTTP.HTTPRequest].Path.decode('utf-8', errors='ignore')
                                event_summary = f"HTTP Request: {src_ip}:{src_port} -> {dst_ip}:{dst_port} Method: {http_method}, Host: {http_host}, Path: {http_path[:50]}..."
                            elif "HTTP/" in payload:
                                http_method = payload.split(' ')[0] if ' ' in payload else 'UNKNOWN'
                                http_path = payload.split(' ')[1] if len(payload.split(' ')) > 1 else 'UNKNOWN'
                                event_summary = f"HTTP Traffic: {src_ip}:{src_port} -> {dst_ip}:{dst_port} Method: {http_method}, Path: {http_path[:50]}..."
                        except Exception:
                            pass

                elif dst_port == 443 or src_port == 443:
                    event_summary = f"HTTPS Traffic: {src_ip}:{src_port} <-> {dst_ip}:{dst_port} (Encrypted)"

                elif dst_port in [22, 3389] or src_port in [22, 3389]:
                    protocol = "SSH" if dst_port == 22 else "RDP" if dst_port == 3389 else "Unknown TCP"
                    event_summary = f"{protocol} Connection: {src_ip}:{src_port} <-> {dst_ip}:{dst_port}"
            
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                self.port_counts[src_port] += 1
                self.port_counts[dst_port] += 1

        if event_summary:
            self.network_events_queue.put(event_summary)
            self.new_event_signal.emit(event_summary)

    def get_llm_analysis(self, events_batch):
        if not events_batch:
            return "No network events collected in this batch for analysis."

        events_text = "\n".join(events_batch)

        system_prompt = (
            "You are an OpSec AI assistant. Your task is to analyze a list of network events "
            "and provide a concise summary, identify any unusual patterns, or flag potential security concerns. "
            "Focus on high-level observations rather than deep technical analysis. "
            "If no unusual patterns are found, state that the traffic appears normal."
        )

        user_prompt = (
            f"Here is a batch of recent network events:\n\n{events_text}\n\n"
            "Please summarize these events and highlight anything that seems unusual or might be an OpSec concern."
        )

        messages = [
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': user_prompt}
        ]

        try:
            response = ollama.chat(
                model=self.llm_model,
                messages=messages,
                options={'temperature': 0.2, 'top_k': 40, 'top_p': 0.9}
            )
            return response['message']['content']
        except ollama.ResponseError as e:
            self.error_signal.emit(f"Error communicating with Ollama: {e}. Is Ollama server running and model '{self.llm_model}' pulled?")
            return f"Error: Could not get LLM analysis ({e})"
        except Exception as e:
            self.error_signal.emit(f"An unexpected error occurred during LLM analysis: {e}")
            return f"Error: An unexpected error occurred during LLM analysis ({e})"

    def run(self):
        self.status_signal.emit(f"Starting network sniffing on interface: {self.interface}...")
        try:
            sniff_thread_handle = threading.Thread(
                target=lambda: sniff(
                    iface=self.interface,
                    prn=self.process_packet,
                    store=0,
                    stop_filter=lambda x: not self._running
                )
            )
            sniff_thread_handle.daemon = True
            sniff_thread_handle.start()

            while self._running:
                current_time = time.time()

                while not self.network_events_queue.empty():
                    self.processed_events.append(self.network_events_queue.get())

                if (current_time - self.last_batch_time >= self.batch_duration and self.processed_events) or \
                   len(self.processed_events) >= self.max_events:

                    batch_to_send = self.processed_events[:self.max_events]
                    self.processed_events[:] = self.processed_events[self.max_events:]

                    if batch_to_send:
                        self.status_signal.emit("Sending events to LLM for analysis...")
                        analysis = self.get_llm_analysis(batch_to_send)
                        self.llm_analysis_signal.emit(analysis)
                    else:
                        self.status_signal.emit(f"No new events for LLM analysis in the last {self.batch_duration} seconds.")

                    self.last_batch_time = current_time

                # --- Handle Stats Update ---
                if current_time - self.last_stats_update_time >= self.STATS_UPDATE_INTERVAL:
                    top_ips = self.ip_counts.most_common(7)
                    top_ports = self.port_counts.most_common(7)
                    self.most_used_signal.emit(top_ips, top_ports)
                    # Debug print to confirm signal emission
                    print(f"DEBUG: Emitting most_used_signal with IPs: {top_ips}, Ports: {top_ports}")
                    self.last_stats_update_time = current_time

                time.sleep(0.1)

            if sniff_thread_handle.is_alive():
                sniff_thread_handle.join(timeout=2)
                if sniff_thread_handle.is_alive():
                    self.error_signal.emit("Warning: Sniffing thread did not terminate gracefully.")

        except Exception as e:
            self.error_signal.emit(f"Critical error in sniffing worker: {e}. Make sure you run as Administrator and Npcap is installed.")
            self._running = False
        finally:
            self.status_signal.emit("Network sniffing worker stopped.")


# --- Main GUI Application ---
class OpSecWatcherGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OpSec Network Watcher")
        self.setGeometry(100, 100, 1200, 750)

        self.worker_thread = None
        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # --- Top Panel: Configuration and Stats ---
        top_panel_layout = QHBoxLayout()
        main_layout.addLayout(top_panel_layout)

        # Left side: Configuration Group Box
        config_group_box = QGroupBox("Configuration")
        config_layout = QVBoxLayout(config_group_box)
        
        form_layout = QHBoxLayout()
        form_layout.addWidget(QLabel("Interface:"))
        self.interface_input = QLineEdit("Wi-Fi")
        form_layout.addWidget(self.interface_input)
        form_layout.addWidget(QLabel("LLM Model:"))
        self.llm_model_input = QComboBox()
        self.llm_model_input.addItems(["ALIENTELLIGENCE/cybersecuritythreatanalysisv2:latest","llama3", "tinyllama", "nomic-embed-text"])
        self.llm_model_input.setCurrentText("llama3")
        form_layout.addWidget(self.llm_model_input)
        form_layout.addWidget(QLabel("Batch Duration (s):"))
        self.batch_duration_input = QSpinBox()
        self.batch_duration_input.setRange(5, 300)
        self.batch_duration_input.setValue(30)
        form_layout.addWidget(self.batch_duration_input)
        form_layout.addWidget(QLabel("Max Events:"))
        self.max_events_input = QSpinBox()
        self.max_events_input.setRange(1, 200)
        self.max_events_input.setValue(15)
        form_layout.addWidget(self.max_events_input)
        config_layout.addLayout(form_layout)

        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Watching")
        self.start_button.clicked.connect(self.start_watching)
        button_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Watching")
        self.stop_button.clicked.connect(self.stop_watching)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        config_layout.addLayout(button_layout)

        top_panel_layout.addWidget(config_group_box)


        # Right side: Most Used Stats Group Box
        stats_group_box = QGroupBox("Most Used")
        stats_layout = QHBoxLayout(stats_group_box)

        ips_layout = QVBoxLayout()
        ips_layout.addWidget(QLabel("<b>Top IPs:</b>"))
        self.most_used_ips_display = QTextEdit()
        self.most_used_ips_display.setReadOnly(True)
        self.most_used_ips_display.setMinimumHeight(100)
        ips_layout.addWidget(self.most_used_ips_display)
        stats_layout.addLayout(ips_layout)

        ports_layout = QVBoxLayout()
        ports_layout.addWidget(QLabel("<b>Top Ports:</b>"))
        self.most_used_ports_display = QTextEdit()
        self.most_used_ports_display.setReadOnly(True)
        self.most_used_ports_display.setMinimumHeight(100)
        ports_layout.addWidget(self.most_used_ports_display)
        stats_layout.addLayout(ports_layout)

        top_panel_layout.addWidget(stats_group_box)
        top_panel_layout.setStretch(0, 3)
        top_panel_layout.setStretch(1, 2)


        self.status_label = QLabel("Status: Ready to start.")
        main_layout.addWidget(self.status_label)


        main_layout.addWidget(QLabel("<h2>Network Events:</h2>"))
        self.event_display = QTextEdit()
        self.event_display.setReadOnly(True)
        self.event_display.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.event_display.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        main_layout.addWidget(self.event_display)

        main_layout.addWidget(QLabel("<h2>LLM Analysis:</h2>"))
        self.llm_analysis_display = QTextEdit()
        self.llm_analysis_display.setReadOnly(True)
        self.llm_analysis_display.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        main_layout.addWidget(self.llm_analysis_display)

    @pyqtSlot()
    def start_watching(self):
        if self.worker_thread is not None and self.worker_thread.isRunning():
            QMessageBox.warning(self, "Warning", "Watcher is already running!")
            return

        interface = self.interface_input.text().strip()
        llm_model = self.llm_model_input.currentText()
        batch_duration = self.batch_duration_input.value()
        max_events = self.max_events_input.value()

        if not interface:
            QMessageBox.warning(self, "Input Error", "Please enter a network interface name.")
            return

        self.event_display.clear()
        self.llm_analysis_display.clear()
        self.most_used_ips_display.clear()
        self.most_used_ports_display.clear()
        self.status_label.setText("Status: Starting...")

        self.worker_thread = NetworkSnifferWorker(interface, llm_model, batch_duration, max_events)
        self.worker_thread.new_event_signal.connect(self.append_event)
        self.worker_thread.llm_analysis_signal.connect(self.display_llm_analysis)
        self.worker_thread.most_used_signal.connect(self.update_most_used_displays)
        self.worker_thread.error_signal.connect(self.display_error)
        self.worker_thread.status_signal.connect(self.status_label.setText)

        self.worker_thread.finished.connect(self.on_worker_finished)

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        self.worker_thread.start()
        print(f"GUI started worker for interface: {interface}")

    @pyqtSlot()
    def stop_watching(self):
        if self.worker_thread is not None and self.worker_thread.isRunning():
            self.status_label.setText("Status: Stopping network watcher...")
            self.worker_thread.stop()
            self.worker_thread.wait()
            print("GUI stopped worker.")
        else:
            QMessageBox.information(self, "Info", "Watcher is not running.")

    @pyqtSlot(str)
    def append_event(self, event_summary):
        self.event_display.append(event_summary)
        self.event_display.verticalScrollBar().setValue(self.event_display.verticalScrollBar().maximum())

    @pyqtSlot(str)
    def display_llm_analysis(self, analysis_text):
        self.llm_analysis_display.append("\n--- NEW LLM ANALYSIS ---")
        self.llm_analysis_display.append(analysis_text)
        self.llm_analysis_display.append("------------------------\n")
        self.llm_analysis_display.verticalScrollBar().setValue(self.llm_analysis_display.verticalScrollBar().maximum())

    @pyqtSlot(list, list)
    def update_most_used_displays(self, top_ips, top_ports):
        print(f"DEBUG: GUI received top_ips: {top_ips}, top_ports: {top_ports}") # Debug print
        ip_text = ""
        for ip, count in top_ips:
            ip_text += f"{ip} ({count})\n"
        self.most_used_ips_display.setText(ip_text)

        port_text = ""
        for port, count in top_ports:
            port_text += f"{port} ({count})\n"
        self.most_used_ports_display.setText(port_text)
        print("DEBUG: GUI updated most used displays.") # Debug print

    @pyqtSlot(str)
    def display_error(self, error_message):
        QMessageBox.critical(self, "Error", error_message)
        self.status_label.setText(f"Status: Error - {error_message}")
        self.stop_watching()

    @pyqtSlot()
    def on_worker_finished(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_label.setText("Status: Ready to start.")
        print("Worker thread finished.")

    def closeEvent(self, event):
        if self.worker_thread is not None and self.worker_thread.isRunning():
            reply = QMessageBox.question(self, 'Confirm Exit',
                                         "Sniffing is active. Do you want to stop it and exit?",
                                         QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                         QMessageBox.StandardButton.No)
            if reply == QMessageBox.StandardButton.Yes:
                self.stop_watching()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


if __name__ == "__main__":
    import threading

    app = QApplication(sys.argv)
    window = OpSecWatcherGUI()
    window.show()
    sys.exit(app.exec())
