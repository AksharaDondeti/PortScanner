import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox,simpledialog
import queue
import csv
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime
import matplotlib.pyplot as plt
import uuid
import nmap
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph
import webbrowser,os,subprocess

# Flag to control the scanning process
scanning = False

# Queue to store scan results
scan_queue = queue.Queue()

# Function to identify service based on port
def get_service_name(port, protocol):
    service_map = {
        80: "HTTP",
        443: "HTTPS",
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        110: "POP3",
        23: "Telnet",
        53: "DNS",
        3389: "RDP",
        1433: "MSSQL",
        3306: "MySQL",
        5432: "PostgreSQL",
        445: "SMB",
    }
    return service_map.get(port, "Unknown")



def detect_os(ip):
    try:
        # Ping the target to get TTL value
        output = subprocess.check_output(["ping", "-c", "1", ip], stderr=subprocess.STDOUT, universal_newlines=True)
        
        # Search for TTL in the output
        ttl = None
        for line in output.splitlines():
            if "ttl" in line.lower():
                ttl = int(line.split("ttl=")[1].split()[0])
                break

        # Map TTL to OS
        if ttl is not None:
            if ttl <= 64:
                return "Linux"
            elif ttl <= 128:
                return "Windows"
            elif ttl <= 255:
                return "BSD or macOS"
            else:
                return "Unknown OS"
        else:
            return "Unable to detect OS"
    except Exception as e:
        return f"Error: {e}"



def scan_tcp_port(ip, port, output, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    service = get_service_name(port, "TCP")
    try:
        sock.connect((ip, port))
        banner = ""
        try:
            if port in [80, 443]:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode().strip()
            elif port == 21:  # FTP
                banner = sock.recv(1024).decode().strip()
            elif port == 22:  # SSH
                banner = sock.recv(1024).decode().strip()
            elif port == 25:  # SMTP
                banner = sock.recv(1024).decode().strip()
            else:
                sock.sendall(b"\r\n")
                banner = sock.recv(1024).decode().strip()
        except:
            banner = "Unknown version"
        
        banner = banner.replace("\n", " ").replace("\r", " ")
        output.put((port, "TCP", "Open", banner, service))
    except socket.timeout:
        output.put((port, "TCP", "Closed", "Timeout", service))
    except Exception as e:
        output.put((port, "TCP", "Closed", str(e), service)) 
    finally:
        sock.close()

def scan_udp_port(ip, port, output, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    service = get_service_name(port, "UDP")
    try:
        sock.sendto(b"\x00\x01", (ip, port))
        data, _ = sock.recvfrom(1024)
        banner = data.decode().strip()
        
        banner = banner.replace("\n", " ").replace("\r", " ")
        output.put((port, "UDP", "Open", banner if banner else "Unknown version", service))
    except socket.timeout:
        output.put((port, "UDP", "Closed", "Timeout", service))
    except Exception as e:
        output.put((port, "UDP", "Closed", str(e), service))
    finally:
        sock.close()


def save_results_to_pdf(result_table, target_entry):
    
    target = target_entry.get()  
    
    
    specific_ports = specific_ports_entry.get()
    ports = specific_ports.split(",") if specific_ports else "1-65535"
    ports = ",".join(ports)  

    
    pdf_name = simpledialog.askstring("Input", "Enter the PDF file name:", initialvalue="scan_results.pdf")
    if not pdf_name:
        pdf_name = f"scan_results_{uuid.uuid4().hex}.pdf"
    if not pdf_name.lower().endswith('.pdf'):
        pdf_name += ".pdf"

    pdf_file = pdf_name
    c = canvas.Canvas(pdf_file, pagesize=letter)

    try:
        
        c.drawImage("logo.png", 100, 730, width=100, height=50)  
    except:
        print("Logo not found, skipping.")
    
    
    c.setFont("Helvetica-Bold", 16)
    c.drawString(150, 700, "Port Scanner Results") 


    c.setFont("Helvetica", 10)
    c.drawString(150, 685, f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    c.drawString(150, 670, f"Target: {target}")
    c.drawString(150, 655, f"Ports Scanned: {ports}")

    left_margin = 100
    y_position = 620  
    line_height = 14

    c.setFont("Helvetica-Bold", 12)
    c.drawString(left_margin, y_position, "Scan Results:")
    y_position -= line_height

    def wrap_text(c, text, x, y, max_width=450):
        lines = []
        width, height = c.stringWidth(text, "Helvetica", 10), 0
        if width > max_width:
            while text:
                for i in range(len(text), 0, -1):
                    line = text[:i]
                    width = c.stringWidth(line, "Helvetica", 10)
                    if width <= max_width:
                        lines.append(line)
                        text = text[i:].lstrip()
                        break
        else:
            lines.append(text)

        for line in lines:
            c.drawString(x, y, line)
            y -= line_height
        return y

   
    content = result_table.get_children()
    for item in content:
        values = result_table.item(item, "values")

        port = values[0]
        protocol = values[1]
        status = values[2]
        banner = values[3]

        text_lines = [
            f"Port: {port}",
            f"Protocol: {protocol}",
            f"Status: {status}",
            f"Banner: {banner}",
        ]

        
        for line in text_lines:
            if y_position < 100:
                c.showPage() 
                c.setFont("Helvetica-Bold", 16)
                c.drawString(150, 780, "Port Scanner Results")
                c.setFont("Helvetica", 10)
                c.drawString(150, 765, f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                c.drawString(150, 750, f"Target: {target}")
                c.setFont("Helvetica-Bold", 10)
                y_position = 680 

            
            if line.startswith("Port:"):
                c.setFont("Helvetica-Bold", 10)
            else:
                c.setFont("Helvetica", 10)

            
            y_position = wrap_text(c, line, left_margin, y_position)

    
    c.save()

    messagebox.showinfo("Save to PDF", f"Results saved to {pdf_file}")



def save_results_to_csv(result_table):
    csv_name = simpledialog.askstring("Input", "Enter the CSV file name:", initialvalue="scan_results.csv")
   
    if not csv_name:
        csv_name = f"scan_results_{uuid.uuid4().hex}.csv"
    
    if not csv_name.lower().endswith('.csv'):
        csv_name += ".csv"
    
    content = result_table.get_children()
    
   
    with open(csv_name, mode='w', newline='') as file:
        writer = csv.writer(file)
        
        writer.writerow(["Port", "Protocol", "Status", "Banner", "Service"])
    
        for item in content:
            values = result_table.item(item, "values")
            writer.writerow(values)
    messagebox.showinfo("Save to CSV", f"Results saved to {csv_name}")


def scan_ports():
    global scanning
    scanning = True
    target = target_entry.get()
    specific_ports = specific_ports_entry.get()
    start_port = start_port_entry.get()
    end_port = end_port_entry.get()

    scan_all = scan_all_var.get()

    # Check if specific ports are provided; otherwise, require start and end ports
    if not specific_ports and not scan_all and (not start_port or not end_port):
        messagebox.showerror("Error", "Please enter both start and end ports or specific ports.")
        return

    scan_all = scan_all_var.get()
    protocol = protocol_var.get()
    timeout = int(timeout_entry.get()) if timeout_entry.get() else 1  # Set timeout

    result_table.delete(*result_table.get_children())  # Clear previous results
    open_ports = []

    if scan_all:
        start_port = 0
        end_port = 65535
        ports_to_scan = range(start_port, end_port + 1)
    elif specific_ports:
        ports_to_scan = list(map(int, specific_ports.split(',')))  # Use specific ports
    else:
        start_port = int(start_port)
        end_port = int(end_port)
        ports_to_scan = range(start_port, end_port + 1)

    def scan_and_update(port):
        if not scanning:
            return
        if protocol in ["TCP", "BOTH"]:
            scan_tcp_port(target, port, scan_queue, timeout)
        if protocol in ["UDP", "BOTH"]:
            scan_udp_port(target, port, scan_queue, timeout)
        while not scan_queue.empty():
            port, proto, status, banner, service = scan_queue.get()
            result_table.insert("", "end", values=(port, proto, status, banner, service)) 
            if status == "Open":
                open_ports.append(port)

    for port in ports_to_scan:
        if not scanning:
            break
        scan_and_update(port)

    # OS Detection
    os_info = detect_os(target)
    os_label.config(text=f"Detected OS: {os_info}")
    
    if open_ports:
        messagebox.showinfo("Open Ports", f"Open ports: {', '.join(map(str, open_ports))}")
    else:
        messagebox.showinfo("Open Ports", "No open ports found.")


def plot_results():
    # Create a list of all rows from the result_table
    open_ports_count = 0
    closed_ports_count = 0

    for item in result_table.get_children():
        values = result_table.item(item, "values")
        if values[2] == "Open":
            open_ports_count += 1
        else:
            closed_ports_count += 1

    labels = 'Open', 'Closed'
    sizes = [open_ports_count, closed_ports_count]
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
    plt.axis('equal')
    plt.show()


def start_scan():
    scan_thread = threading.Thread(target=scan_ports)
    scan_thread.daemon = True
    scan_thread.start()

def stop_scan():
    global scanning
    scanning = False

def show_local_ip():
    local_ip = socket.gethostbyname(socket.gethostname())
    messagebox.showinfo("Local IP", f"Your local IP address is: {local_ip}")

def show_domain_ip():
    target = target_entry.get()
    try:
        domain_ip = socket.gethostbyname(target)
        messagebox.showinfo("Domain IP", f"The IP address of {target} is: {domain_ip}")
    except socket.gaierror:
        messagebox.showerror("Error", "Invalid domain name")

def show_project_info():
   file_path = "developer.html"
   webbrowser.open(file_path)

# Create the main window
root = tk.Tk()
root.title("Advanced Port Scanner")

# Create and place the widgets
main_frame = ttk.Frame(root, padding="10")
main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Label and Entry for Target
ttk.Label(main_frame, text="Target (IP or Domain):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
target_entry = ttk.Entry(main_frame, width=30)
target_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.E)

# Label and Entry for Specific Ports
ttk.Label(main_frame, text="Specific Ports (comma-separated):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
specific_ports_entry = ttk.Entry(main_frame, width=30)
specific_ports_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.E)

# Label and Entry for Start Port
ttk.Label(main_frame, text="Start Port:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
start_port_entry = ttk.Entry(main_frame, width=10)
start_port_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.E)

# Label and Entry for End Port
ttk.Label(main_frame, text="End Port:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
end_port_entry = ttk.Entry(main_frame, width=10)
end_port_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.E)

# Label and Entry for Timeout
ttk.Label(main_frame, text="Timeout (seconds):").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
timeout_entry = ttk.Entry(main_frame, width=10)
timeout_entry.grid(row=4, column=1, padx=5, pady=5, sticky=tk.E)

# Adjust column widths to ensure consistency and alignment
main_frame.grid_columnconfigure(0, weight=1, uniform="equal")  # Align first column (labels)
main_frame.grid_columnconfigure(1, weight=1, uniform="equal")

scan_all_var = tk.BooleanVar()
scan_all_check = ttk.Checkbutton(main_frame, text="Scan All Ports (0-65535)", variable=scan_all_var)
scan_all_check.grid(row=5, column=0, columnspan=2, pady=5)

protocol_var = ttk.Combobox(main_frame, values=["TCP", "UDP", "BOTH"], state="readonly")
protocol_var.set("TCP")
protocol_var.grid(row=6, column=0, padx=5, pady=5, sticky=tk.W)

scan_button = ttk.Button(main_frame, text="Start Scan", command=start_scan)
scan_button.grid(row=7, column=0, padx=5, pady=5, sticky=tk.W)

stop_button = ttk.Button(main_frame, text="Stop Scan", command=stop_scan)
stop_button.grid(row=7, column=1, padx=5, pady=5, sticky=tk.E)

result_table = ttk.Treeview(main_frame, columns=("Port", "Protocol", "Status", "Banner", "Service"), show="headings", height=10)
result_table.heading("Port", text="Port")
result_table.heading("Protocol", text="Protocol")
result_table.heading("Status", text="Status")
result_table.heading("Banner", text="Banner")
result_table.heading("Service", text="Service")
result_table.grid(row=8, column=0, columnspan=2, pady=5, sticky=(tk.W, tk.E))

os_label = ttk.Label(main_frame, text="Detected OS: Unknown")
os_label.grid(row=9, column=0, columnspan=2, pady=5)

save_pdf_button = ttk.Button(main_frame, text="Save to PDF", command=lambda: save_results_to_pdf(result_table,target_entry))
save_pdf_button.grid(row=10, column=0, padx=5, pady=5, sticky=tk.W)

save_csv_button = ttk.Button(main_frame, text="Save to CSV", command=lambda: save_results_to_csv(result_table))
save_csv_button.grid(row=10, column=1, padx=5, pady=5, sticky=tk.E)

plot_button = ttk.Button(main_frame, text="Plot Results", command=plot_results)
plot_button.grid(row=11, column=0, columnspan=2, pady=5)

ip_tools_frame = ttk.Frame(root, padding="10")
ip_tools_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

local_ip_button = ttk.Button(ip_tools_frame, text="Show Local IP", command=show_local_ip)
local_ip_button.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

domain_ip_button = ttk.Button(ip_tools_frame, text="Show Domain IP", command=show_domain_ip)
domain_ip_button.grid(row=0, column=1, padx=5, pady=5, sticky=tk.E)

project_info_button = ttk.Button(ip_tools_frame, text="Show Project Info", command=show_project_info)
project_info_button.grid(row=1, column=0, columnspan=2, pady=5)

root.mainloop()
