import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Global flag to stop scanning
stop_scanning = False

# Function to resolve a domain/host to its IP address
def resolve_host(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

# Function to scan a specific TCP/UDP port
def scan_port(ip, port, protocol, result_table):
    global stop_scanning
    if stop_scanning:
        return

    try:
        banner = "N/A"
        if protocol == "TCP":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                if sock.connect_ex((ip, port)) == 0:
                    try:
                        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode(errors="ignore").strip()
                    except:
                        banner = "Unknown"
                    try:
                        service = socket.getservbyport(port, "tcp")
                    except:
                        service = "Unknown"
                    result_table.insert("", "end", values=(port, service, "TCP", "Open", banner))
        elif protocol == "UDP":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1)
                sock.sendto(b"Ping", (ip, port))
                try:
                    data, _ = sock.recvfrom(1024)
                    banner = data.decode(errors="ignore").strip()
                except:
                    pass
                try:
                    service = socket.getservbyport(port, "udp")
                except:
                    service = "Unknown"
                result_table.insert("", "end", values=(port, service, "UDP", "Open", banner))
    except Exception as e:
        print(f"Error scanning port {port}: {e}")

# Function to scan ports within a range
def scan_ports(target, start_port, end_port, protocol, result_table):
    global stop_scanning
    stop_scanning = False

    ip = resolve_host(target)
    if not ip:
        messagebox.showerror("Error", "Invalid Target Address")
        return

    for port in range(start_port, end_port + 1):
        if stop_scanning:
            break
        if protocol == "Both":
            scan_port(ip, port, "TCP", result_table)
            scan_port(ip, port, "UDP", result_table)
        else:
            scan_port(ip, port, protocol, result_table)

    if not stop_scanning:
        messagebox.showinfo("Scan Complete", "Port scanning is complete!")

# Function to start scanning
def start_scan(target_entry, start_port_entry, end_port_entry, protocol_var, result_table, scan_button):
    global stop_scanning
    stop_scanning = False

    target = target_entry.get().strip()
    start_port = start_port_entry.get().strip()
    end_port = end_port_entry.get().strip()

    # Validate inputs
    if not target:
        messagebox.showerror("Error", "Target cannot be empty!")
        return

    if not start_port.isdigit() or not end_port.isdigit():
        messagebox.showerror("Error", "Port range must be numeric!")
        return

    start_port = int(start_port)
    end_port = int(end_port)

    if start_port < 0 or end_port > 65535 or start_port > end_port:
        messagebox.showerror("Error", "Port range must be between 0 and 65535.")
        return

    protocol = protocol_var.get()
    if protocol not in ["TCP", "UDP", "Both"]:
        messagebox.showerror("Error", "Please select a valid protocol!")
        return

    # Clear previous results
    result_table.delete(*result_table.get_children())

    # Disable scan button
    scan_button.config(state="disabled")

    # Start scanning in a thread
    threading.Thread(
        target=lambda: [scan_ports(target, start_port, end_port, protocol, result_table),
                        scan_button.config(state="normal")]
    ).start()

# Function to stop scanning
def stop_scan():
    global stop_scanning
    stop_scanning = True
    messagebox.showinfo("Scan Stopped", "Port scanning has been stopped.")

# Function to save results to a PDF
def save_results(result_table):
    if not result_table.get_children():
        messagebox.showerror("Error", "No results to save!")
        return

    file_name = "scan_results.pdf"
    pdf = canvas.Canvas(file_name, pagesize=letter)
    pdf.setFont("Helvetica", 10)

    pdf.drawString(30, 750, "Port Scanner Results")
    pdf.drawString(30, 735, "-" * 50)

    y = 715
    for child in result_table.get_children():
        values = result_table.item(child, "values")
        pdf.drawString(30, y, f"Port: {values[0]}, Service: {values[1]}, Protocol: {values[2]}, Status: {values[3]}, Banner: {values[4]}")
        y -= 15
        if y < 50:
            pdf.showPage()
            y = 750

    pdf.save()
    messagebox.showinfo("Success", f"Results saved to {file_name}")

# Function to display project info
def show_info():
    info_text = (
        "Advanced Port Scanner\n"
        "Version: 1.0\n"
        "Author: Your Name\n"
        "Description: A Python-based tool to scan TCP/UDP ports, "
        "resolve hostnames, grab banners, and save results to a PDF."
    )
    messagebox.showinfo("Project Info", info_text)

# Tkinter UI
def create_ui():
    root = tk.Tk()
    root.title("Advanced Port Scanner")
    root.geometry("900x750")
    root.configure(bg="black")

    # Title
    title_label = tk.Label(root, text="Advanced Port Scanner", fg="green", bg="black", font=("Courier", 20, "bold"))
    title_label.pack(pady=10)

    # Input Fields
    frame = tk.Frame(root, bg="black")
    frame.pack(pady=10)

    tk.Label(frame, text="Target (IP or Domain):", fg="green", bg="black", font=("Courier", 12)).grid(row=0, column=0, padx=5, sticky="w")
    target_entry = tk.Entry(frame, width=20, font=("Courier", 12))
    target_entry.grid(row=0, column=1, padx=5)

    tk.Label(frame, text="Start Port:", fg="green", bg="black", font=("Courier", 12)).grid(row=1, column=0, padx=5, sticky="w")
    start_port_entry = tk.Entry(frame, width=10, font=("Courier", 12))
    start_port_entry.grid(row=1, column=1, padx=5, sticky="w")

    tk.Label(frame, text="End Port:", fg="green", bg="black", font=("Courier", 12)).grid(row=2, column=0, padx=5, sticky="w")
    end_port_entry = tk.Entry(frame, width=10, font=("Courier", 12))
    end_port_entry.grid(row=2, column=1, padx=5, sticky="w")

    # Protocol Selection
    protocol_var = tk.StringVar(value="TCP")
    tk.Label(frame, text="Protocol:", fg="green", bg="black", font=("Courier", 12)).grid(row=3, column=0, padx=5, sticky="w")
    protocol_menu = ttk.Combobox(frame, textvariable=protocol_var, values=["TCP", "UDP", "Both"], state="readonly", font=("Courier", 12))
    protocol_menu.grid(row=3, column=1, padx=5, sticky="w")

    # Buttons
    scan_button = tk.Button(root, text="Start Scan", fg="black", bg="green", font=("Courier", 12, "bold"),
                             command=lambda: start_scan(target_entry, start_port_entry, end_port_entry, protocol_var, result_table, scan_button))
    scan_button.pack(pady=5)

    stop_button = tk.Button(root, text="Stop Scan", fg="black", bg="red", font=("Courier", 12, "bold"), command=stop_scan)
    stop_button.pack(pady=5)

    save_button = tk.Button(root, text="Save Results to PDF", fg="black", bg="blue", font=("Courier", 12, "bold"), command=lambda: save_results(result_table))
    save_button.pack(pady=5)

    info_button = tk.Button(root, text="Show Info", fg="black", bg="yellow", font=("Courier", 12, "bold"), command=show_info)
    info_button.pack(pady=5)

    # Results Table
    columns = ("Port", "Service", "Protocol", "Status", "Banner")
    result_table = ttk.Treeview(root, columns=columns, show="headings", height=15)
    for col in columns:
        result_table.heading(col, text=col)
        result_table.column(col, width=150)
    result_table.pack(pady=10)

    root.mainloop()

# Run the UI
if __name__ == "__main__":
    create_ui()
