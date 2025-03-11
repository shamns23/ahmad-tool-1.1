import sys
import os
import subprocess
import netifaces
import logging
import ipaddress
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QPushButton, QLabel, QLineEdit, QPlainTextEdit, QMessageBox, QStatusBar,
    QGridLayout, QComboBox, QProgressBar, QGroupBox, QSpinBox, QFileDialog
)
from PySide6.QtCore import QThread, Signal, Slot, QSettings
from PySide6.QtGui import QColor, QTextCharFormat, QFont
import platform
import ctypes

# إعداد سجل الأخطاء
logging.basicConfig(
    filename='network_tool.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# إعدادات التطبيق
SETTINGS = QSettings("xAI", "NetworkTool")
IS_WINDOWS = platform.system() == "Windows"

def is_root():
    """تحقق من صلاحيات الـ Root/Administrator"""
    if IS_WINDOWS:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    return os.geteuid() == 0 if hasattr(os, 'geteuid') else False

def get_local_ip():
    """احصل على عنوان الـ IP المحلي"""
    try:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    ip = addr['addr']
                    if not ip.startswith("127."):
                        return ip
    except Exception as e:
        logging.error(f"Error getting local IP: {e}")
    return "Unknown"

def get_network_interfaces():
    """احصل على قائمة الواجهات الشبكية"""
    try:
        return netifaces.interfaces()
    except Exception as e:
        logging.error(f"Error getting network interfaces: {e}")
        return []

def check_tool_installed(tool_name):
    """التحقق من تثبيت أداة معينة"""
    try:
        subprocess.run([tool_name, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

class NmapThread(QThread):
    update = Signal(str)
    finished_signal = Signal()
    progress_signal = Signal(int)

    def __init__(self, target, scan_type, iface):
        super().__init__()
        self.target = target
        self.scan_type = scan_type
        self.iface = iface
        self.process = None

    def run(self):
        try:
            if not check_tool_installed("nmap"):
                self.update.emit("❌ Nmap is not installed. Please install it first.\n")
                self.progress_signal.emit(100)
                self.finished_signal.emit()
                return
            sudo_prefix = "" if IS_WINDOWS else "sudo " if is_root() else ""
            command = f"{sudo_prefix}nmap -T4 {'-e ' + self.iface if self.iface and not IS_WINDOWS else ''} {self.scan_type} {self.target}"
            self.process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            progress = 0
            for line in self.process.stdout:
                self.update.emit(line)
                if "Scanning" in line and progress < 30: progress = 30
                elif "PORT" in line and progress < 50: progress = 50
                elif "OS" in line and progress < 70: progress = 70
                elif "Network Distance" in line and progress < 90: progress = 90
                self.progress_signal.emit(progress)
            for line in self.process.stderr:
                self.update.emit(f"⚠️ {line}")
            self.process.wait()
            if self.process.returncode != 0:
                self.update.emit(f"❌ Error: Nmap scan failed with code {self.process.returncode}\n")
            self.progress_signal.emit(100)
            self.finished_signal.emit()
        except Exception as e:
            self.update.emit(f"❌ Error: {str(e)}\n")
            self.progress_signal.emit(100)
            self.finished_signal.emit()

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate() if IS_WINDOWS else self.process.kill()

class BettercapThread(QThread):
    update = Signal(str)
    finished_signal = Signal()
    progress_signal = Signal(int)

    def __init__(self, target_ip, iface):
        super().__init__()
        self.target_ip = target_ip
        self.iface = iface
        self.cap_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bettercap.cap")
        self.process = None

    def run(self):
        if IS_WINDOWS:
            self.update.emit("❌ Bettercap is not supported on Windows.\n")
            self.progress_signal.emit(100)
            self.finished_signal.emit()
            return
        try:
            if not check_tool_installed("bettercap"):
                self.update.emit("❌ Bettercap is not installed. Please install it first.\n")
                self.progress_signal.emit(100)
                self.finished_signal.emit()
                return
            with open(self.cap_file_path, "w") as cap_file:
                cap_file.write(f"net.probe on\nset arp.spoof.fullduplex true\nset arp.spoof.targets {self.target_ip}\narp.spoof on\nnet.sniff on\n")
            self.progress_signal.emit(10)
            command = f"sudo bettercap -iface {self.iface} -caplet {self.cap_file_path}"
            self.process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.progress_signal.emit(30)
            line_count = 0
            for line in self.process.stdout:
                self.update.emit(line)
                line_count += 1
                if line_count % 5 == 0:
                    self.progress_signal.emit(min(30 + line_count, 90))
            for line in self.process.stderr:
                self.update.emit(f"⚠️ {line}")
            self.process.wait()
            if self.process.returncode != 0:
                self.update.emit(f"❌ Error: Bettercap failed with code {self.process.returncode}\n")
            self.progress_signal.emit(100)
            self.finished_signal.emit()
        except Exception as e:
            self.update.emit(f"❌ Error: {str(e)}\n")
            self.progress_signal.emit(100)
            self.finished_signal.emit()
        finally:
            if os.path.exists(self.cap_file_path):
                os.remove(self.cap_file_path)

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.kill()

class PingSweepThread(QThread):
    update = Signal(str)
    device_found = Signal(str, str)
    finished_signal = Signal()
    progress_signal = Signal(int)

    def __init__(self, target, timeout=1, max_threads=100):
        super().__init__()
        self.target = target
        self.timeout = timeout
        self.max_threads = max_threads
        self.should_stop = False
        self.total_ips = 0
        self.completed_ips = 0

    def ping(self, ip):
        try:
            if self.should_stop:
                return None
            ping_cmd = f"ping -n 1 -w {self.timeout * 1000} {ip}" if IS_WINDOWS else f"ping -c 1 -W {self.timeout} {ip}"
            start_time = time.time()
            result = subprocess.run(ping_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            end_time = time.time()
            self.completed_ips += 1
            self.progress_signal.emit(int((self.completed_ips / self.total_ips) * 100))
            if result.returncode == 0:
                latency = round((end_time - start_time) * 1000, 2)
                hostname = ""
                try:
                    hostname_cmd = f"nslookup {ip}" if IS_WINDOWS else f"host {ip}"
                    hostname_result = subprocess.run(hostname_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if hostname_result.returncode == 0:
                        for line in hostname_result.stdout.split('\n'):
                            if "name" in line.lower() or "domain name pointer" in line.lower():
                                hostname = line.split('=')[-1].strip() if '=' in line else line.split('pointer')[-1].strip()
                                hostname = hostname.rstrip('.')
                                break
                except:
                    pass
                return f"🟢 {ip} - استجابة: {latency} مللي ثانية {hostname}\n", (ip, hostname)
            return None, None
        except Exception as e:
            return f"⚠️ خطأ عند محاولة ping لـ {ip}: {str(e)}\n", None

    def run(self):
        try:
            start_time = datetime.now()
            self.update.emit(f"🔍 بدء مسح ping sweep على {self.target} في {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            ip_range = self.get_ip_range()
            self.total_ips = len(ip_range)
            if not self.total_ips:
                self.update.emit("⚠️ لم يتم العثور على عناوين IP صالحة.\n")
                self.progress_signal.emit(100)
                self.finished_signal.emit()
                return
            self.update.emit(f"🔢 تم العثور على {self.total_ips} عنوان IP للمسح.\n")
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = {executor.submit(self.ping, ip): ip for ip in ip_range}
                for future in futures:
                    if self.should_stop:
                        break
                    result, device = future.result()
                    if result:
                        self.update.emit(result)
                    if device:
                        self.device_found.emit(*device)
            duration = (datetime.now() - start_time).total_seconds()
            self.update.emit(f"\n✅ اكتمل المسح في {duration:.2f} ثانية.\n")
        except Exception as e:
            self.update.emit(f"❌ خطأ: {str(e)}\n")
        finally:
            self.progress_signal.emit(100)
            self.finished_signal.emit()

    def get_ip_range(self):
        """استخراج نطاق IP من الهدف"""
        ip_range = []
        try:
            if '/' in self.target:
                network = ipaddress.ip_network(self.target, strict=False)
                ip_range = [str(ip) for ip in network.hosts()]
            elif '-' in self.target:
                start_ip, end_ip = self.target.split('-')
                start_parts = start_ip.strip().split('.')
                end_parts = end_ip.strip().split('.')
                if len(end_parts) == 1:
                    end_parts = start_parts[:-1] + end_parts
                start = int(ipaddress.ip_address('.'.join(start_parts)))
                end = int(ipaddress.ip_address('.'.join(end_parts)))
                ip_range = [str(ipaddress.ip_address(i)) for i in range(start, end + 1)]
            else:
                ip_range = [self.target]
        except Exception as e:
            logging.error(f"Error parsing IP range: {e}")
        return ip_range

    def stop(self):
        self.should_stop = True

class NetworkTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔥 Network Test Tool - Cross-Platform")
        self.resize(1200, 900)
        self.local_ip = get_local_ip()
        self.is_root = is_root()
        self.interfaces = get_network_interfaces()
        self.active_threads = []
        self.initUI()
        self.load_settings()

    def initUI(self):
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        if not self.is_root:
            QMessageBox.warning(self, "⚠️ Warning", "Run as Administrator (Windows) or sudo (Linux) for full functionality!")
        self.createNmapTab()
        self.createBettercapTab()
        self.createPingSweepTab()

    def create_tab(self, title):
        tab = QWidget()
        layout = QGridLayout(tab)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)
        self.tabs.addTab(tab, title)
        return tab, layout

    def format_text(self, text_edit, text):
        cursor = text_edit.textCursor()
        fmt = QTextCharFormat()
        fmt.setFont(QFont("Monospace", 10))
        if "🟢" in text:
            fmt.setForeground(QColor("green"))
        elif "⚠️" in text:
            fmt.setForeground(QColor("orange"))
        elif "❌" in text:
            fmt.setForeground(QColor("red"))
        else:
            fmt.setForeground(QColor("white"))
        cursor.insertText(text, fmt)
        text_edit.setTextCursor(cursor)

    def createNmapTab(self):
        tab, layout = self.create_tab("🌐 Nmap Scan")
        layout.addWidget(QLabel("🎯 Target:"), 0, 0)
        self.nmapTargetEdit = QLineEdit(self.local_ip)
        layout.addWidget(self.nmapTargetEdit, 0, 1)
        layout.addWidget(QLabel("📡 Scan Type:"), 1, 0)
        self.scanOption = QComboBox()
        self.scanOption.addItems(["🔍 Device Scan Only", "🌐 Full Network Scan"])
        self.scanOption.currentIndexChanged.connect(self.update_scan_target)
        layout.addWidget(self.scanOption, 1, 1)
        layout.addWidget(QLabel("🌐 Interface:"), 2, 0)
        self.interfaceComboBox = QComboBox()
        self.interfaceComboBox.addItems(self.interfaces)
        if IS_WINDOWS:
            self.interfaceComboBox.setEnabled(False)
        layout.addWidget(self.interfaceComboBox, 2, 1)
        layout.addWidget(QLabel("📊 Progress:"), 3, 0)
        self.nmapProgressBar = QProgressBar()
        layout.addWidget(self.nmapProgressBar, 3, 1)
        self.nmapResultText = QPlainTextEdit(readOnly=True)
        layout.addWidget(self.nmapResultText, 4, 0, 1, 2)
        buttons = QHBoxLayout()
        scans = {"🔍 Quick (-sS)": "-sS", "🔍 Version (-sV)": "-sV", "🖥️ OS (-O)": "-O", "🚀 Aggressive (-A)": "-A"}
        for label, scan_type in scans.items():
            btn = QPushButton(label)
            btn.setStyleSheet("background-color: #4CAF50; color: white; padding: 10px;")
            btn.clicked.connect(lambda _, t=scan_type: self.startNmapScan(t))
            buttons.addWidget(btn)
        self.stopNmapButton = QPushButton("⛔ Stop")
        self.stopNmapButton.setStyleSheet("background-color: #F44336; color: white; padding: 10px;")
        self.stopNmapButton.clicked.connect(self.stopNmapScan)
        self.stopNmapButton.setEnabled(False)
        buttons.addWidget(self.stopNmapButton)
        layout.addLayout(buttons, 5, 0, 1, 2)

    def update_scan_target(self):
        self.nmapTargetEdit.setText(f"{self.local_ip}/24" if self.scanOption.currentIndex() == 1 else self.local_ip)

    def startNmapScan(self, scan_type):
        target, iface = self.nmapTargetEdit.text().strip(), self.interfaceComboBox.currentText().strip()
        if not target:
            QMessageBox.critical(self, "Error", "Enter a valid target.")
            return
        self.nmapResultText.clear()
        self.nmapProgressBar.setValue(0)
        self.statusBar.showMessage(f"Running Nmap {scan_type} on {target}...", 5000)
        self.nmap_thread = NmapThread(target, scan_type, iface if not IS_WINDOWS else "")
        self.nmap_thread.update.connect(lambda t: self.format_text(self.nmapResultText, t))
        self.nmap_thread.finished_signal.connect(self.onNmapFinished)
        self.nmap_thread.progress_signal.connect(self.nmapProgressBar.setValue)
        self.active_threads.append(self.nmap_thread)
        self.nmap_thread.start()
        self.stopNmapButton.setEnabled(True)

    def stopNmapScan(self):
        if hasattr(self, 'nmap_thread') and self.nmap_thread.isRunning():
            self.nmap_thread.stop()
            self.statusBar.showMessage("Nmap stopped.", 5000)
            self.stopNmapButton.setEnabled(False)

    @Slot()
    def onNmapFinished(self):
        self.statusBar.showMessage("Nmap finished.", 5000)
        self.stopNmapButton.setEnabled(False)
        if hasattr(self, 'nmap_thread'):
            self.active_threads.remove(self.nmap_thread)

    def createBettercapTab(self):
        tab, layout = self.create_tab("Bettercap")
        layout.addWidget(QLabel("🎯 Target:"), 0, 0)
        self.bettercapTargetEdit = QLineEdit(self.local_ip)
        layout.addWidget(self.bettercapTargetEdit, 0, 1)
        layout.addWidget(QLabel("🌐 Interface:"), 1, 0)
        self.bettercapInterfaceComboBox = QComboBox()
        self.bettercapInterfaceComboBox.addItems(self.interfaces)
        layout.addWidget(self.bettercapInterfaceComboBox, 1, 1)
        layout.addWidget(QLabel("📊 Progress:"), 2, 0)
        self.bettercapProgressBar = QProgressBar()
        layout.addWidget(self.bettercapProgressBar, 2, 1)
        self.bettercapResultText = QPlainTextEdit(readOnly=True)
        layout.addWidget(self.bettercapResultText, 3, 0, 1, 2)
        buttons = QHBoxLayout()
        self.startBettercapButton = QPushButton("💻 Run")
        self.startBettercapButton.setStyleSheet("background-color: #FF5722; color: white; padding: 10px;")
        self.startBettercapButton.clicked.connect(self.startBettercap)
        buttons.addWidget(self.startBettercapButton)
        self.stopBettercapButton = QPushButton("⛔ Stop")
        self.stopBettercapButton.setStyleSheet("background-color: #F44336; color: white; padding: 10px;")
        self.stopBettercapButton.clicked.connect(self.stopBettercap)
        self.stopBettercapButton.setEnabled(False)
        buttons.addWidget(self.stopBettercapButton)
        layout.addLayout(buttons, 4, 0, 1, 2)
        if IS_WINDOWS:
            self.startBettercapButton.setEnabled(False)
            self.format_text(self.bettercapResultText, "❌ Bettercap is not supported on Windows.\n")

    def startBettercap(self):
        target, iface = self.bettercapTargetEdit.text().strip(), self.bettercapInterfaceComboBox.currentText().strip()
        if not target or not iface:
            QMessageBox.critical(self, "Error", "Enter a valid target and interface.")
            return
        if not self.is_root:
            QMessageBox.warning(self, "Warning", "Bettercap requires root privileges.")
        self.bettercapResultText.clear()
        self.bettercapProgressBar.setValue(0)
        self.statusBar.showMessage(f"Running Bettercap on {target}...", 5000)
        self.bettercap_thread = BettercapThread(target, iface)
        self.bettercap_thread.update.connect(lambda t: self.format_text(self.bettercapResultText, t))
        self.bettercap_thread.finished_signal.connect(self.onBettercapFinished)
        self.bettercap_thread.progress_signal.connect(self.bettercapProgressBar.setValue)
        self.active_threads.append(self.bettercap_thread)
        self.bettercap_thread.start()
        self.stopBettercapButton.setEnabled(True)
        self.startBettercapButton.setEnabled(False)

    def stopBettercap(self):
        if hasattr(self, 'bettercap_thread') and self.bettercap_thread.isRunning():
            self.bettercap_thread.stop()
            self.statusBar.showMessage("Bettercap stopped.", 5000)
            self.stopBettercapButton.setEnabled(False)
            self.startBettercapButton.setEnabled(True)

    @Slot()
    def onBettercapFinished(self):
        self.statusBar.showMessage("Bettercap finished.", 5000)
        self.stopBettercapButton.setEnabled(False)
        self.startBettercapButton.setEnabled(True)
        if hasattr(self, 'bettercap_thread'):
            self.active_threads.remove(self.bettercap_thread)

    def createPingSweepTab(self):
        tab, layout = self.create_tab("🔍 Ping Sweep")
        layout.addWidget(QLabel("🎯 Target Range:"), 0, 0)
        self.pingSweepTargetEdit = QLineEdit(f"{self.local_ip}/24")
        layout.addWidget(self.pingSweepTargetEdit, 0, 1)
        options = QGroupBox("🔧 Options")
        opt_layout = QGridLayout()
        opt_layout.addWidget(QLabel("⏱️ Timeout (s):"), 0, 0)
        self.timeoutSpinBox = QSpinBox()
        self.timeoutSpinBox.setRange(1, 10)
        self.timeoutSpinBox.setValue(1)
        opt_layout.addWidget(self.timeoutSpinBox, 0, 1)
        opt_layout.addWidget(QLabel("🧵 Max Threads:"), 1, 0)
        self.threadsSpinBox = QSpinBox()
        self.threadsSpinBox.setRange(10, 500)
        self.threadsSpinBox.setValue(100)
        opt_layout.addWidget(self.threadsSpinBox, 1, 1)
        options.setLayout(opt_layout)
        layout.addWidget(options, 1, 0, 1, 2)
        layout.addWidget(QLabel("📊 Progress:"), 2, 0)
        self.pingSweepProgressBar = QProgressBar()
        layout.addWidget(self.pingSweepProgressBar, 2, 1)
        results = QGroupBox("📝 Results")
        res_layout = QVBoxLayout()
        self.pingSweepResultText = QPlainTextEdit(readOnly=True)
        res_layout.addWidget(self.pingSweepResultText)
        self.devicesFoundLabel = QLabel("🖥️ Active Devices: 0")
        res_layout.addWidget(self.devicesFoundLabel)
        results.setLayout(res_layout)
        layout.addWidget(results, 3, 0, 1, 2)
        buttons = QHBoxLayout()
        self.startPingSweepButton = QPushButton("🚀 Start")
        self.startPingSweepButton.setStyleSheet("background-color: #2196F3; color: white; padding: 10px;")
        self.startPingSweepButton.clicked.connect(self.startPingSweep)
        buttons.addWidget(self.startPingSweepButton)
        self.stopPingSweepButton = QPushButton("⛔ Stop")
        self.stopPingSweepButton.setStyleSheet("background-color: #F44336; color: white; padding: 10px;")
        self.stopPingSweepButton.clicked.connect(self.stopPingSweep)
        self.stopPingSweepButton.setEnabled(False)
        buttons.addWidget(self.stopPingSweepButton)
        self.exportButton = QPushButton("💾 Export")
        self.exportButton.setStyleSheet("background-color: #9E9E9E; color: white; padding: 10px;")
        self.exportButton.clicked.connect(self.exportResults)
        buttons.addWidget(self.exportButton)
        layout.addLayout(buttons, 4, 0, 1, 2)
        self.discovered_devices = []

    def startPingSweep(self):
        target = self.pingSweepTargetEdit.text().strip()
        if not target:
            QMessageBox.critical(self, "Error", "Enter a valid IP range.")
            return
        self.pingSweepResultText.clear()
        self.pingSweepProgressBar.setValue(0)
        self.discovered_devices = []
        self.devicesFoundLabel.setText("🖥️ Active Devices: 0")
        self.statusBar.showMessage(f"Running Ping Sweep on {target}...", 5000)
        self.ping_sweep_thread = PingSweepThread(target, self.timeoutSpinBox.value(), self.threadsSpinBox.value())
        self.ping_sweep_thread.update.connect(lambda t: self.format_text(self.pingSweepResultText, t))
        self.ping_sweep_thread.device_found.connect(self.addDiscoveredDevice)
        self.ping_sweep_thread.finished_signal.connect(self.onPingSweepFinished)
        self.ping_sweep_thread.progress_signal.connect(self.pingSweepProgressBar.setValue)
        self.active_threads.append(self.ping_sweep_thread)
        self.ping_sweep_thread.start()
        self.stopPingSweepButton.setEnabled(True)
        self.startPingSweepButton.setEnabled(False)

    def stopPingSweep(self):
        if hasattr(self, 'ping_sweep_thread') and self.ping_sweep_thread.isRunning():
            self.ping_sweep_thread.stop()
            self.statusBar.showMessage("Ping Sweep stopped.", 5000)
            self.stopPingSweepButton.setEnabled(False)
            self.startPingSweepButton.setEnabled(True)

    @Slot(str, str)
    def addDiscoveredDevice(self, ip, hostname):
        self.discovered_devices.append((ip, hostname))
        self.devicesFoundLabel.setText(f"🖥️ Active Devices: {len(self.discovered_devices)}")

    @Slot()
    def onPingSweepFinished(self):
        self.statusBar.showMessage("Ping Sweep finished.", 5000)
        self.stopPingSweepButton.setEnabled(False)
        self.startPingSweepButton.setEnabled(True)
        if self.discovered_devices:
            self.format_text(self.pingSweepResultText, "\n📋 Summary of Discovered Devices:\n")
            for i, (ip, hostname) in enumerate(self.discovered_devices, 1):
                self.format_text(self.pingSweepResultText, f"{i}. {hostname or ip} ({ip})\n")
        if hasattr(self, 'ping_sweep_thread'):
            self.active_threads.remove(self.ping_sweep_thread)

    def exportResults(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "Export Results", "", "Text Files (*.txt)")
        if file_name:
            with open(file_name, 'w', encoding='utf-8') as f:
                f.write(self.pingSweepResultText.toPlainText())
            self.statusBar.showMessage(f"Results exported to {file_name}", 5000)

    def load_settings(self):
        self.nmapTargetEdit.setText(SETTINGS.value("nmap_target", self.local_ip))
        self.bettercapTargetEdit.setText(SETTINGS.value("bettercap_target", self.local_ip))
        self.pingSweepTargetEdit.setText(SETTINGS.value("ping_target", f"{self.local_ip}/24"))
        self.timeoutSpinBox.setValue(SETTINGS.value("ping_timeout", 1, type=int))
        self.threadsSpinBox.setValue(SETTINGS.value("ping_threads", 100, type=int))

    def save_settings(self):
        SETTINGS.setValue("nmap_target", self.nmapTargetEdit.text())
        SETTINGS.setValue("bettercap_target", self.bettercapTargetEdit.text())
        SETTINGS.setValue("ping_target", self.pingSweepTargetEdit.text())
        SETTINGS.setValue("ping_timeout", self.timeoutSpinBox.value())
        SETTINGS.setValue("ping_threads", self.threadsSpinBox.value())

    def closeEvent(self, event):
        self.save_settings()
        super().closeEvent(event)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    # ستايل شيت جذري مع تصميم عصري، تدرج لوني، وحواف مستديرة
    app.setStyleSheet("""
        QMainWindow {
            background: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:1, stop:0 #0f2027, stop:1 #203a43);
            color: #e0e0e0;
        }
        QLabel {
            font-family: 'Segoe UI', sans-serif;
            font-size: 15px;
            color: #e0e0e0;
        }
        QLineEdit, QPlainTextEdit, QComboBox, QSpinBox {
            background-color: #1e2a30;
            color: #ffffff;
            border: 2px solid #3b4a54;
            border-radius: 8px;
            padding: 6px;
        }
        QPushButton {
            background-color: #3b8eea;
            color: #ffffff;
            border: none;
            padding: 10px;
            border-radius: 8px;
            font-family: 'Segoe UI';
            font-size: 14px;
        }
        QPushButton:hover {
            background-color: #347fda;
        }
        QPushButton:pressed {
            background-color: #2a69c7;
        }
        QProgressBar {
            border: 2px solid #3b4a54;
            border-radius: 8px;
            background-color: #1e2a30;
            text-align: center;
            color: #e0e0e0;
        }
        QProgressBar::chunk {
            background-color: #3b8eea;
            border-radius: 8px;
        }
        QTabWidget::pane {
            border: none;
            background: transparent;
        }
        QTabBar::tab {
            background: #1e2a30;
            color: #e0e0e0;
            padding: 10px 20px;
            border: 1px solid #3b4a54;
            border-bottom: none;
            border-top-left-radius: 10px;
            border-top-right-radius: 10px;
            margin-right: 2px;
        }
        QTabBar::tab:selected {
            background: #3b8eea;
            font-weight: bold;
        }
        QStatusBar {
            background-color: #1e2a30;
            color: #e0e0e0;
            border-top: 2px solid #3b4a54;
        }
        QGroupBox {
            border: 2px solid #3b4a54;
            border-radius: 10px;
            margin-top: 1.5em;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 8px;
            background-color: #3b8eea;
            color: #ffffff;
            border-radius: 5px;
        }
    """)
    window = NetworkTool()
    window.show()
    sys.exit(app.exec())
