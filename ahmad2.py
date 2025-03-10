import sys
import socket
import subprocess
import platform
import ipaddress
import re
import netifaces
import requests

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QPushButton, QLabel, QLineEdit, QPlainTextEdit, QMessageBox, QStatusBar, QGridLayout
)
from PySide6.QtCore import QThread, Signal, Slot

# التحقق من توفر المكتبات الخارجية
try:
    import nmap
    nmap_available = True
except ImportError:
    nmap_available = False

try:
    import dns.resolver
    dns_resolver_available = True
except ImportError:
    dns_resolver_available = False

try:
    import whois
    whois_available = True
except ImportError:
    whois_available = False

#############################################
# تعريف خيوط العمل (Threads) للمهام الخلفية #
#############################################

class PortScanThread(QThread):
    update = Signal(str)
    finished_signal = Signal()

    def __init__(self, host, port_start, port_end):
        super().__init__()
        self.host = host
        self.port_start = port_start
        self.port_end = port_end
        self._running = True

    def run(self):
        try:
            for port in range(self.port_start, self.port_end + 1):
                if not self._running:
                    break
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.host, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "Unknown"
                    self.update.emit(f"Port {port} open - Service: {service}\n")
                sock.close()
            self.update.emit("Port scan completed.\n")
        except Exception as e:
            self.update.emit(f"Error during port scan: {str(e)}\n")
        self.finished_signal.emit()

    def cancel(self):
        self._running = False

class DeviceScanThread(QThread):
    update = Signal(str)
    finished_signal = Signal()

    def __init__(self, network_range):
        super().__init__()
        self.network_range = network_range
        self._running = True

    def run(self):
        try:
            ip_net = ipaddress.ip_network(self.network_range, strict=False)
        except Exception as e:
            self.update.emit(f"Invalid network range: {str(e)}\n")
            self.finished_signal.emit()
            return

        # الحصول على عناوين MAC للجهاز المحلي
        my_macs = set()
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_LINK in addrs:
                for addr in addrs[netifaces.AF_LINK]:
                    if 'addr' in addr:
                        my_macs.add(addr['addr'].lower())

        found_devices = 0
        self.update.emit("IP\t\tStatus\t\tMAC\t\t\tHostname\n" + "-"*80 + "\n")
        for ip in ip_net.hosts():
            if not self._running:
                self.update.emit("Device scan canceled.\n")
                self.finished_signal.emit()
                return
            ip_str = str(ip)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip_str, 80))
                sock.close()
                if result == 0:
                    try:
                        hostname = socket.getfqdn(ip_str)
                        if hostname == ip_str:
                            hostname = "Unknown"
                    except:
                        hostname = "Unknown"
                    mac = self.get_mac(ip_str, my_macs)
                    status = "This Device" if mac.lower() in my_macs else "Online"
                    self.update.emit(f"{ip_str}\t{status}\t{mac}\t{hostname}\n")
                    found_devices += 1
            except Exception:
                continue
        self.update.emit(f"\nFound {found_devices} devices on the network.\n")
        self.finished_signal.emit()

    def get_mac(self, ip_str, my_macs):
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output(f"arp -a {ip_str}", shell=True, stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
                for line in output.splitlines():
                    if ip_str in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1].replace('-', ':')
            else:
                output = subprocess.check_output(["arp", "-n", ip_str], stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
                for line in output.splitlines():
                    if ip_str in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[2]
        except:
            pass
        return "Unknown"

    def cancel(self):
        self._running = False

class DNSLookupThread(QThread):
    update = Signal(str)
    finished_signal = Signal()

    def __init__(self, domain):
        super().__init__()
        self.domain = domain

    def run(self):
        output = f"Performing DNS lookup for {self.domain}...\n\n"
        # سجلات A (IPv4)
        try:
            a_records = socket.getaddrinfo(self.domain, None, socket.AF_INET)
            ipv4_addrs = {record[4][0] for record in a_records}
            output += "=== A Records (IPv4) ===\n" + "\n".join(ipv4_addrs) + "\n"
        except Exception as e:
            output += f"No A Records (IPv4): {str(e)}\n"
        # سجلات AAAA (IPv6)
        try:
            aaaa_records = socket.getaddrinfo(self.domain, None, socket.AF_INET6)
            ipv6_addrs = {record[4][0] for record in aaaa_records}
            output += "\n=== AAAA Records (IPv6) ===\n" + "\n".join(ipv6_addrs) + "\n"
        except Exception as e:
            output += f"\nNo AAAA Records (IPv6): {str(e)}\n"
        # سجلات MX
        if dns_resolver_available:
            try:
                mx_records = dns.resolver.resolve(self.domain, 'MX')
                output += "\n=== MX Records ===\n"
                for mx in mx_records:
                    output += f"{mx.exchange} (Priority: {mx.preference})\n"
            except Exception as e:
                output += f"\nError querying MX records: {str(e)}\n"
        else:
            output += "\nInstall dnspython for MX records (pip install dnspython)\n"
        # سجلات NS
        if dns_resolver_available:
            try:
                ns_records = dns.resolver.resolve(self.domain, 'NS')
                output += "\n=== NS Records ===\n"
                for ns in ns_records:
                    output += f"{ns}\n"
            except Exception as e:
                output += f"\nError querying NS records: {str(e)}\n"
        else:
            output += "\nInstall dnspython for NS records (pip install dnspython)\n"
        self.update.emit(output)
        self.finished_signal.emit()

class WhoisLookupThread(QThread):
    update = Signal(str)
    finished_signal = Signal()

    def __init__(self, domain):
        super().__init__()
        self.domain = domain

    def run(self):
        output = f"Performing WHOIS lookup for {self.domain}...\n\n"
        try:
            if whois_available:
                w = whois.whois(self.domain)
                output += str(w)
            else:
                output += "Install python-whois (pip install python-whois)\n"
                output += f"Alternative: Visit https://www.whois.com/whois/{self.domain}\n"
        except Exception as e:
            output += f"Error: {str(e)}\n"
        self.update.emit(output)
        self.finished_signal.emit()

class NmapScanThread(QThread):
    update = Signal(str)
    finished_signal = Signal()

    def __init__(self, target, scan_type):
        super().__init__()
        self.target = target
        self.scan_type = scan_type
        self._running = True

    def run(self):
        if not nmap_available:
            self.update.emit("Python-nmap library not installed.\n")
            self.finished_signal.emit()
            return
        try:
            subprocess.run(['nmap', '--version'], capture_output=True, check=True)
        except Exception:
            self.update.emit("Nmap is not installed or not found.\n")
            self.finished_signal.emit()
            return

        self.update.emit(f"Running Nmap {self.scan_type} scan on {self.target}...\n\n")
        try:
            nm = nmap.PortScanner()
            arguments = f"{self.scan_type} -T4"
            if self.scan_type == "-O":
                arguments += " -O"
            elif self.scan_type == "-sV":
                arguments += " -sV"
            elif self.scan_type == "-A":
                arguments += " -A"
            nm.scan(hosts=self.target, arguments=arguments)
            self.update.emit("Nmap Scan Results:\n" + "-"*80 + "\n")
            for host in nm.all_hosts():
                if not self._running:
                    self.update.emit("\nScan canceled by user.\n")
                    self.finished_signal.emit()
                    return
                state = nm[host].state()
                self.update.emit(f"Host: {host} ({state})\n")
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        port_state = nm[host][proto][port]['state']
                        service = nm[host][proto][port].get('name', 'Unknown')
                        version = nm[host][proto][port].get('version', 'Unknown')
                        self.update.emit(f"Port: {port}\tState: {port_state}\tService: {service}\tVersion: {version}\n")
            self.update.emit(f"\nNmap {self.scan_type} scan completed for {self.target}\n")
        except Exception as e:
            self.update.emit(f"Error during Nmap scan: {str(e)}\n")
        self.finished_signal.emit()

    def cancel(self):
        self._running = False

class BettercapThread(QThread):
    update = Signal(str)
    finished_signal = Signal()

    def __init__(self, target):
        super().__init__()
        self.target = target
        self._running = True

    def run(self):
        try:
            command = f"bettercap -iface eth0 -target {self.target} -no-color"
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            while True:
                if not self._running:
                    process.terminate()
                    self.update.emit("\nBettercap canceled by user.\n")
                    self.finished_signal.emit()
                    return
                output_line = process.stdout.readline()
                if output_line == '' and process.poll() is not None:
                    break
                if output_line:
                    self.update.emit(output_line)
            self.update.emit(f"\nBettercap completed for {self.target}\n")
        except Exception as e:
            self.update.emit(f"Error during Bettercap execution: {str(e)}\n")
        self.finished_signal.emit()

    def cancel(self):
        self._running = False

#############################################
# التطبيق الرئيسي باستخدام PySide6        #
#############################################

class NetworkTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Network Tool - PySide6 Version")
        self.resize(1100, 800)
        self.initUI()

    def initUI(self):
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)

        self.createBasicInfoTab()
        self.createPortScannerTab()
        self.createDeviceScannerTab()
        self.createDNSLookupTab()
        self.createNetworkAnalysisTab()

    ###########################
    # تبويب المعلومات الأساسية #
    ###########################
    def createBasicInfoTab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        self.basicInfoText = QPlainTextEdit()
        self.basicInfoText.setReadOnly(True)
        layout.addWidget(self.basicInfoText)
        refreshButton = QPushButton("Refresh")
        refreshButton.clicked.connect(self.getNetworkInfo)
        layout.addWidget(refreshButton)
        tab.setLayout(layout)
        self.tabs.addTab(tab, "Basic Info")
        self.getNetworkInfo()

    def getNetworkInfo(self):
        try:
            info = f"Operating System: {platform.system()} {platform.release()}\n"
            info += f"Hostname: {socket.gethostname()}\n"
            info += f"Local IP Address: {socket.gethostbyname(socket.gethostname())}\n"
            self.basicInfoText.setPlainText(info)
            self.statusBar.showMessage("Network info retrieved.", 5000)
        except Exception as e:
            self.basicInfoText.setPlainText(f"Error retrieving network info: {str(e)}\n")
            self.statusBar.showMessage("Error retrieving network info", 5000)

    ###########################
    # تبويب فحص البورتات      #
    ###########################
    def createPortScannerTab(self):
        tab = QWidget()
        layout = QGridLayout()
        layout.addWidget(QLabel("Host:"), 0, 0)
        self.portHostEdit = QLineEdit()
        layout.addWidget(self.portHostEdit, 0, 1)
        layout.addWidget(QLabel("Ports (e.g., 20-80):"), 1, 0)
        self.portRangeEdit = QLineEdit()
        layout.addWidget(self.portRangeEdit, 1, 1)
        self.portResultText = QPlainTextEdit()
        self.portResultText.setReadOnly(True)
        layout.addWidget(self.portResultText, 2, 0, 1, 2)
        startScanButton = QPushButton("Start Scan")
        startScanButton.clicked.connect(self.startPortScan)
        layout.addWidget(startScanButton, 3, 0, 1, 2)
        tab.setLayout(layout)
        self.tabs.addTab(tab, "Port Scanner")

    def startPortScan(self):
        host = self.portHostEdit.text().strip()
        port_range = self.portRangeEdit.text().strip()
        if not host:
            QMessageBox.critical(self, "Error", "Please enter a host to scan.")
            return
        try:
            start_str, end_str = port_range.split('-')
            start_port = int(start_str)
            end_port = int(end_str)
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError
        except:
            QMessageBox.critical(self, "Error", "Please enter a valid port range (e.g., 20-80).")
            return
        self.portResultText.clear()
        self.statusBar.showMessage("Starting port scan...", 5000)
        self.port_thread = PortScanThread(host, start_port, end_port)
        self.port_thread.update.connect(self.appendPortResult)
        self.port_thread.finished_signal.connect(lambda: self.statusBar.showMessage("Port scan completed.", 5000))
        self.port_thread.start()

    @Slot(str)
    def appendPortResult(self, text):
        self.portResultText.insertPlainText(text)

    ###########################
    # تبويب فحص الأجهزة       #
    ###########################
    def createDeviceScannerTab(self):
        tab = QWidget()
        layout = QGridLayout()
        layout.addWidget(QLabel("Network Range (e.g., 192.168.1.0/24):"), 0, 0)
        self.deviceRangeEdit = QLineEdit()
        layout.addWidget(self.deviceRangeEdit, 0, 1)
        self.deviceResultText = QPlainTextEdit()
        self.deviceResultText.setReadOnly(True)
        layout.addWidget(self.deviceResultText, 1, 0, 1, 2)
        startScanButton = QPushButton("Start Scan")
        startScanButton.clicked.connect(self.startDeviceScan)
        layout.addWidget(startScanButton, 2, 0)
        cancelScanButton = QPushButton("Cancel Scan")
        cancelScanButton.clicked.connect(self.cancelDeviceScan)
        layout.addWidget(cancelScanButton, 2, 1)
        tab.setLayout(layout)
        self.tabs.addTab(tab, "Device Scanner")

    def startDeviceScan(self):
        network_range = self.deviceRangeEdit.text().strip()
        if not network_range:
            QMessageBox.critical(self, "Error", "Please enter a network range (e.g., 192.168.1.0/24).")
            return
        self.deviceResultText.clear()
        self.statusBar.showMessage("Starting device scan...", 5000)
        self.device_thread = DeviceScanThread(network_range)
        self.device_thread.update.connect(self.appendDeviceResult)
        self.device_thread.finished_signal.connect(lambda: self.statusBar.showMessage("Device scan completed.", 5000))
        self.device_thread.start()

    @Slot(str)
    def appendDeviceResult(self, text):
        self.deviceResultText.insertPlainText(text)

    def cancelDeviceScan(self):
        if hasattr(self, 'device_thread'):
            self.device_thread.cancel()
            self.statusBar.showMessage("Device scan canceled.", 5000)

    ###########################
    # تبويب DNS/WHOIS         #
    ###########################
    def createDNSLookupTab(self):
        tab = QWidget()
        layout = QGridLayout()
        layout.addWidget(QLabel("Domain Name:"), 0, 0)
        self.domainEdit = QLineEdit()
        layout.addWidget(self.domainEdit, 0, 1)
        self.dnsResultText = QPlainTextEdit()
        self.dnsResultText.setReadOnly(True)
        layout.addWidget(self.dnsResultText, 1, 0, 1, 2)
        dnsButton = QPushButton("DNS Lookup")
        dnsButton.clicked.connect(self.startDNSLookup)
        layout.addWidget(dnsButton, 2, 0)
        whoisButton = QPushButton("WHOIS Lookup")
        whoisButton.clicked.connect(self.startWhoisLookup)
        layout.addWidget(whoisButton, 2, 1)
        tab.setLayout(layout)
        self.tabs.addTab(tab, "DNS Lookup")

    def startDNSLookup(self):
        domain = self.domainEdit.text().strip()
        if not domain or not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$', domain):
            QMessageBox.critical(self, "Error", "Please enter a valid domain name (e.g., google.com).")
            return
        self.dnsResultText.clear()
        self.statusBar.showMessage(f"Performing DNS lookup for {domain}...", 5000)
        self.dns_thread = DNSLookupThread(domain)
        self.dns_thread.update.connect(self.appendDNSResult)
        self.dns_thread.finished_signal.connect(lambda: self.statusBar.showMessage(f"DNS lookup completed for {domain}.", 5000))
        self.dns_thread.start()

    @Slot(str)
    def appendDNSResult(self, text):
        self.dnsResultText.insertPlainText(text)

    def startWhoisLookup(self):
        domain = self.domainEdit.text().strip()
        if not domain or not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$', domain):
            QMessageBox.critical(self, "Error", "Please enter a valid domain name (e.g., google.com).")
            return
        self.dnsResultText.clear()
        self.statusBar.showMessage(f"Performing WHOIS lookup for {domain}...", 5000)
        self.whois_thread = WhoisLookupThread(domain)
        self.whois_thread.update.connect(self.appendDNSResult)
        self.whois_thread.finished_signal.connect(lambda: self.statusBar.showMessage(f"WHOIS lookup completed for {domain}.", 5000))
        self.whois_thread.start()

    ###########################
    # تبويب تحليل الشبكة       #
    ###########################
    def createNetworkAnalysisTab(self):
        tab = QWidget()
        layout = QGridLayout()
        layout.addWidget(QLabel("Target (e.g., 192.168.1.0/24):"), 0, 0)
        self.analysisTargetEdit = QLineEdit()
        layout.addWidget(self.analysisTargetEdit, 0, 1)
        self.analysisResultText = QPlainTextEdit()
        self.analysisResultText.setReadOnly(True)
        layout.addWidget(self.analysisResultText, 1, 0, 1, 2)
        
        # أزرار فحص nmap
        nmapLayout = QHBoxLayout()
        basicScanButton = QPushButton("Basic Scan (-sS)")
        basicScanButton.clicked.connect(lambda: self.startNmapScan("-sS"))
        nmapLayout.addWidget(basicScanButton)
        versionScanButton = QPushButton("Version Scan (-sV)")
        versionScanButton.clicked.connect(lambda: self.startNmapScan("-sV"))
        nmapLayout.addWidget(versionScanButton)
        osScanButton = QPushButton("OS Detection (-O)")
        osScanButton.clicked.connect(lambda: self.startNmapScan("-O"))
        nmapLayout.addWidget(osScanButton)
        aggressiveScanButton = QPushButton("Aggressive Scan (-A)")
        aggressiveScanButton.clicked.connect(lambda: self.startNmapScan("-A"))
        nmapLayout.addWidget(aggressiveScanButton)
        layout.addLayout(nmapLayout, 2, 0, 1, 2)
        
        # أزرار إضافية للتحليل
        analysisButtonLayout = QHBoxLayout()
        bettercapButton = QPushButton("Run Bettercap")
        bettercapButton.clicked.connect(self.startBettercap)
        analysisButtonLayout.addWidget(bettercapButton)
        cancelAnalysisButton = QPushButton("Cancel Analysis")
        cancelAnalysisButton.clicked.connect(self.cancelAnalysis)
        analysisButtonLayout.addWidget(cancelAnalysisButton)
        # زر تنزيل سكربت (مثال)
        downloadScriptButton = QPushButton("Download Network Script")
        downloadScriptButton.clicked.connect(self.downloadNetworkScript)
        analysisButtonLayout.addWidget(downloadScriptButton)
        # زر تنزيل المتطلبات
        installRequirementsButton = QPushButton("Install Requirements")
        installRequirementsButton.clicked.connect(self.installRequirements)
        analysisButtonLayout.addWidget(installRequirementsButton)
        layout.addLayout(analysisButtonLayout, 3, 0, 1, 2)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "Network Analysis")

    def startNmapScan(self, scan_type):
        target = self.analysisTargetEdit.text().strip()
        if not target:
            QMessageBox.critical(self, "Error", "Please enter a target (e.g., 192.168.1.0/24).")
            return
        self.analysisResultText.clear()
        self.statusBar.showMessage(f"Running Nmap {scan_type} scan on {target}...", 5000)
        self.nmap_thread = NmapScanThread(target, scan_type)
        self.nmap_thread.update.connect(self.appendAnalysisResult)
        self.nmap_thread.finished_signal.connect(lambda: self.statusBar.showMessage(f"Nmap scan completed for {target}.", 5000))
        self.nmap_thread.start()

    @Slot(str)
    def appendAnalysisResult(self, text):
        self.analysisResultText.insertPlainText(text)

    def startBettercap(self):
        target = self.analysisTargetEdit.text().strip()
        if not target:
            QMessageBox.critical(self, "Error", "Please enter a target (e.g., 192.168.1.0/24).")
            return
        self.analysisResultText.clear()
        self.statusBar.showMessage(f"Running Bettercap on {target}...", 5000)
        self.bettercap_thread = BettercapThread(target)
        self.bettercap_thread.update.connect(self.appendAnalysisResult)
        self.bettercap_thread.finished_signal.connect(lambda: self.statusBar.showMessage(f"Bettercap execution completed for {target}.", 5000))
        self.bettercap_thread.start()

    def cancelAnalysis(self):
        if hasattr(self, 'nmap_thread'):
            self.nmap_thread.cancel()
        if hasattr(self, 'bettercap_thread'):
            self.bettercap_thread.cancel()
        self.statusBar.showMessage("Analysis canceled.", 5000)

    ###########################
    # وظائف تنزيل إضافية       #
    ###########################
    # وظيفة تنزيل سكربت الشبكة (مثال)
    def downloadNetworkScript(self):
        # ضع هنا الرابط الحقيقي للسكربت الذي تريد تحميله
        script_url = "http://example.com/network_scan_script.sh"
        try:
            response = requests.get(script_url)
            if response.status_code == 200:
                with open("network_scan_script.sh", "w", encoding="utf-8") as f:
                    f.write(response.text)
                QMessageBox.information(self, "Download Complete", "تم تحميل سكربت الشبكة بنجاح!")
            else:
                QMessageBox.warning(self, "Download Failed", f"فشل تحميل السكربت. رمز الحالة: {response.status_code}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"خطأ أثناء تحميل السكربت: {str(e)}")

    # وظيفة تثبيت المتطلبات (nmap و bettercap)
    def installRequirements(self):
        try:
            # ملاحظة: يستخدم هذا الأمر apt لتثبيت المتطلبات على أنظمة Linux.
            # تأكد من تشغيل التطبيق بصلاحيات sudo أو قم بتعديل الأمر بما يناسب نظامك.
            subprocess.run(["sudo", "apt", "install", "-y", "nmap", "bettercap"], check=True)
            QMessageBox.information(self, "Installation Complete", "تم تثبيت المتطلبات بنجاح!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"حدث خطأ أثناء تثبيت المتطلبات:\n{e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkTool()
    window.show()
    sys.exit(app.exec())
