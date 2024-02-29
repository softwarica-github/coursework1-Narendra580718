import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import nmap

def scan_ports():
    ip_address = ip_entry.get()
    scan_type = scan_type_var.get().upper()

    output_text.delete(1.0, tk.END)  # Clear previous output
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_address, arguments=f'-p 1-65535 -s{scan_type}')
    
    for host in nm.all_hosts():
        output_text.insert(tk.END, f"Host: {host} ({nm[host].hostname()})\n")
        output_text.insert(tk.END, "State: " + nm[host].state() + "\n")
        for proto in nm[host].all_protocols():
            output_text.insert(tk.END, "Protocol: " + proto + "\n")
            ports = nm[host][proto].keys()
            for port in ports:
                output_text.insert(tk.END, f"Port: {port}\tState: {nm[host][proto][port]['state']}\tService: {nm[host][proto][port]['name']}\n")
                # You can access other attributes such as version, reason, etc. if needed
        output_text.insert(tk.END, "\n")

# Create main window
root = tk.Tk()
root.title("Network Mapper (Nmap)")

# IP Address Input
ip_label = tk.Label(root, text="Enter the IP address to scan:")
ip_label.pack()
ip_entry = tk.Entry(root)
ip_entry.pack()

#Explanation text
text1 = ScrolledText(root, height=5, width=40, background="#19231A", foreground="#D8CBC7")
text1.insert(tk.END,"TYPE:\nS = TCP SYN scan \nT = TCP connect scan \nU = UDP scan \nF = TCP FIN scan \nX = Xmas scan ")
text1.pack()

# Scan Type Input
scan_type_label = tk.Label(root, text="Select the Nmap scan type:")
scan_type_label.pack()
scan_type_var = tk.StringVar(root)
scan_type_var.set("S (TCP SYN)")  # Default to TCP SYN scan
scan_type_options = ["S (TCP SYN)", "T (TCP Connect)", "U (UDP)", "F (TCP FIN)", "X (TCP Xmas)"]
scan_type_menu = tk.OptionMenu(root, scan_type_var, *scan_type_options)
scan_type_menu.pack()

# Scan Button
scan_button = tk.Button(root, text="Scan", command=scan_ports, background="#33673B", foreground="white")
scan_button.pack()

# Output Text
output_text = ScrolledText(root, width=80, height=20, background="#9A6D38", foreground="white")
output_text.pack()

root.mainloop()

