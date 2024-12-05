import sys
import ipaddress
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLineEdit, QPushButton, QTabWidget, QLabel, QTextEdit
from PyQt6.QtCore import QThread, pyqtSignal
import requests

class FetchDataThread(QThread):
    data_fetched = pyqtSignal(dict)
    
    def __init__(self, ip_address):
        super().__init__()
        self.ip_address = ip_address

    def Abuse_check(self):
        url = "https://api.abuseipdb.com/api/v2/check"
        # Define the parameters
        params = {
            "ipAddress": self.ip_address,
            "maxAgeInDays": 90,
            "verbose": ""
        }
        
        # Define the headers
        headers = {
            "Key": "PUTAPIKEYHERE",
            "Accept": "application/json"
        }
        
        try:
            response = requests.get(url, params=params, headers=headers)
            response.raise_for_status()
            
            return response.json()
        except requests.exceptions.RequestException as e:
            return None

    def ip_api(self):
        try:
            response = requests.get(f"http://ip-api.com/json/{self.ip_address}?fields=20508671")
            response.raise_for_status()

            return response.json()
        except requests.exceptions.RequestException as e:
            return None           

    def run(self):
        try:
            ipinfo_data = requests.get(f"https://ipinfo.io/{self.ip_address}?token=PUTTOKENHERE").json()

            self.data_fetched.emit({
                'ipinfo': ipinfo_data,
                'abuseipdb': self.Abuse_check(),
                'ip-api': self.ip_api(),
            })
        except Exception as e:
            self.data_fetched.emit({})


class Application(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IP Information Fetcher")
        self.setGeometry(100, 100, 800, 600)

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()

        # Input field and label with IP validation
        self.input_label = QLabel("Enter an IP address:")
        self.input_field = QLineEdit()

        layout.addWidget(self.input_label)
        layout.addWidget(self.input_field)

        # Add Result from validator
        self.result_label = QLabel("")
        layout.addWidget(self.result_label)

        # Create tabs
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)

        # Create four tabs
        self.tab1 = QWidget()
        self.tab2 = QWidget()
        self.tab3 = QWidget()

        self.tab_widget.addTab(self.tab1, "IPInfo")
        self.tab_widget.addTab(self.tab2, "AbuseIPDB")
        self.tab_widget.addTab(self.tab3, "IP-API")

        # Layout for each tab
        layout_tab1 = QVBoxLayout()
        layout_tab2 = QVBoxLayout()
        layout_tab3 = QVBoxLayout()

        self.tab1.setLayout(layout_tab1)
        self.tab2.setLayout(layout_tab2)
        self.tab3.setLayout(layout_tab3)

        # Add widgets to tabs
        self.label_tab1 = QTextEdit("")
        self.label_tab2 = QTextEdit("")
        self.label_tab3 = QTextEdit("")

        self.label_tab1.setReadOnly(True)
        self.label_tab2.setReadOnly(True)
        self.label_tab3.setReadOnly(True)

        layout_tab1.addWidget(self.label_tab1)
        layout_tab2.addWidget(self.label_tab2)
        layout_tab3.addWidget(self.label_tab3)

        # Process button
        self.process_button = QPushButton("Lookup IP address")
        self.process_button.clicked.connect(self.process_data)
        layout.addWidget(self.process_button)

        central_widget.setLayout(layout)

    def process_data(self):
        user_input = self.input_field.text()
        if self.is_valid_ip(user_input):
            self.result_label.setText(f"Fetching data for {user_input}...")
            
            # Start a thread to fetch data
            self.fetch_thread = FetchDataThread(user_input)
            self.fetch_thread.data_fetched.connect(self.update_tabs)
            self.fetch_thread.start()
        else:
            self.result_label.setText("Invalid IP address. Please enter a valid IPv4 or IPv6 address.")

    def update_tabs(self, data):
        ### Start section for IPInfo ###
        # Extracting nested fields for data and then add them to parsed_data
        self.IPINFO = data['ipinfo']
        
        asn_data = self.IPINFO.get('asn', {})
        company_data = self.IPINFO.get('company', {})
        privacy_data = self.IPINFO.get('privacy', {})
        abuse_data = self.IPINFO.get('abuse', {})
        domains_data = self.IPINFO.get('domains', {})

        IPINFO_data = {
            "IP Address": self.IPINFO.get('ip', 'N/A'),
            "Hostname": self.IPINFO.get('hostname', 'N/A'),
            "City": self.IPINFO.get('city', 'N/A'),
            "Region": self.IPINFO.get('region', 'N/A'),
            "Country": self.IPINFO.get('country', 'N/A'),
            "Location Coordinates": f"{self.IPINFO.get('loc', 'N/A').split(',')[0]}, {self.IPINFO.get('loc', 'N/A').split(',')[1]}" if ',' in self.IPINFO.get('loc', '') else 'N/A',
            "Postal Code": self.IPINFO.get('postal', 'N/A'),
            "Timezone": self.IPINFO.get('timezone', 'N/A'),
            "ASN": f"{asn_data.get('asn', 'N/A')} - {asn_data.get('name', 'N/A')}",
            "Company Name": company_data.get('name', 'N/A'),
            "Company Domain": company_data.get('domain', 'N/A'),
            "VPN": privacy_data.get('vpn', False),
            "Proxy": privacy_data.get('proxy', False),
            "Tor": privacy_data.get('tor', False),
            "Relay": privacy_data.get('relay', False),
            "Hosting": privacy_data.get('hosting', False),
            "Service": privacy_data.get('service', 'N/A'),
            "Abuse Address": abuse_data.get('address', 'N/A'),
            "Abuse Country": abuse_data.get('country', 'N/A'),
            "Abuse Email": abuse_data.get('email', 'N/A'),
            "Abuse Name": abuse_data.get('name', 'N/A'),
            "Abuse Network": abuse_data.get('network', 'N/A'),
            "Abuse Phone": abuse_data.get('phone', 'N/A'),
            "Domain Page": domains_data.get('page', 0),
            "Total Domains": domains_data.get('total', 0),
            "Domains List": ', '.join(domains_data.get('domains', [])) if domains_data.get('domains') else 'None'
        }
        ### End section for IPInfo ###

        ### Start section for AbuseIPDB ###
        # Extracting nested fields for data and then add them to parsed_data
        self.ABUSE = data['abuseipdb']['data']
        ABUSE_data = {
            "ipAddress": self.ABUSE.get("ipAddress"),
            "isPublic": self.ABUSE.get("isPublic"),
            "ipVersion": self.ABUSE.get("ipVersion"),
            "isWhitelisted": self.ABUSE.get("isWhitelisted"),
            "abuseConfidenceScore": self.ABUSE.get("abuseConfidenceScore"),
            "countryCode": self.ABUSE.get("countryCode"),
            "countryName": self.ABUSE.get("countryName"),
            "usageType": self.ABUSE.get("usageType"),
            "isp": self.ABUSE.get("isp"),
            "domain": self.ABUSE.get("domain"),
            "hostnames": self.ABUSE.get("hostnames", []),
            "isTor": self.ABUSE.get("isTor"),
            "totalReports": self.ABUSE.get("totalReports"),
            "numDistinctUsers": self.ABUSE.get("numDistinctUsers"),
            "lastReportedAt": self.ABUSE.get("lastReportedAt"),
        }
        ### End section for AbuseIPDB ###
        
        ### Start section for IP API ###
        # Extracting nested fields for data and then add them to parsed_data
        self.IPAPI = data['ip-api']
        IPAPI_data = {
            "query": self.IPAPI.get("query"),
            "country": self.IPAPI.get("country"),
            "countryCode": self.IPAPI.get("countryCode"),
            "region": self.IPAPI.get("region"),
            "regionName": self.IPAPI.get("regionName"),
            "city": self.IPAPI.get("city"),
            "zip": self.IPAPI.get("zip"),
            "latitude": self.IPAPI.get("lat"),
            "longitude": self.IPAPI.get("lon"),
            "timezone": self.IPAPI.get("timezone"),
            "isp": self.IPAPI.get("isp"),
            "organization": self.IPAPI.get("org"),
            "asn": self.IPAPI.get("as")
        }        
        ### End section for IP API ###

        if 'ipinfo' in data:
            self.label_tab1.setPlainText("\n".join([f"{key}: {value}" for key, value in IPINFO_data.items()]))
        if 'abuseipdb' in data:
            self.label_tab2.setPlainText("\n".join([f"{key}: {value}" for key, value in ABUSE_data.items()]))
        if 'ip-api' in data:
            self.label_tab3.setPlainText("\n".join([f"{key}: {value}" for key, value in IPAPI_data.items()]))

        self.result_label.setText("Data fetched successfully.")

    def is_valid_ip(self, ip):
        if self.is_valid_ipv4(ip) or self.is_valid_ipv6(ip):
            return True
        return False

    def is_valid_ipv4(self, ip):
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False

    def is_valid_ipv6(self, ip):
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Application()
    window.show()
    sys.exit(app.exec())
