import unittest
import nmap

def scan_ports(ip_address, scan_type, output_text):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_address, arguments=f'-p 1-65535 -s{scan_type}')

    for host in nm.all_hosts():
        output_text.insert('end', f"Host: {host} ({nm[host].hostname()})\n")
        output_text.insert('end', "State: " + nm[host].state() + "\n")
        for proto in nm[host].all_protocols():
            output_text.insert('end', "Protocol: " + proto + "\n")
            ports = nm[host][proto].keys()
            for port in ports:
                output_text.insert('end', f"Port: {port}\tState: {nm[host][proto][port]['state']}\tService: {nm[host][proto][port]['name']}\n")
        output_text.insert('end', "\n")

class TestScanPorts(unittest.TestCase):
    def test_scan_ports(self):
        ip_address = '127.0.0.1'  # Example IP address
        scan_type = 'S'  # Example scan type
        output_text = OutputTextMock()  # Mock output text widget
        scan_ports(ip_address, scan_type, output_text)

        # Assert statements for expected outputs
        self.assertIn("Host: 127.0.0.1", output_text.text)
        # Add more assertions as needed

class OutputTextMock:
    def __init__(self):
        self.text = ''

    def insert(self, position, text):
        self.text += text

if __name__ == '__main__':
    unittest.main()
