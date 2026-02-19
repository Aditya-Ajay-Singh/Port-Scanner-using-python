import socket
import threading
import queue
import json
import csv
import logging
import subprocess
import platform
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# ================= GLOBALS =================
port_queue = queue.Queue()
open_ports = []
lock = threading.Lock()

# ================= LOGGING =================
logging.basicConfig(
    filename="scanner.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ================= FUNCTIONS =================

def detect_os(ip):
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        output = subprocess.check_output(
            ["ping", param, "1", ip],
            stderr=subprocess.DEVNULL
        ).decode()

        if "ttl=" in output.lower():
            ttl = int(output.lower().split("ttl=")[1].split()[0])
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
        return "Unknown"
    except:
        return "Unknown"

def banner_grab(ip, port, timeout):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(b"Hello\r\n")
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner
    except:
        return "No Banner"

def scan_port(ip, timeout):
    while True:
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            break

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))

            if result == 0:
                banner = banner_grab(ip, port, timeout)
                with lock:
                    open_ports.append({
                        "port": port,
                        "banner": banner
                    })
                    root.after(0, update_output,
                               f"[+] Port {port} OPEN | Banner: {banner}\n")

            s.close()
        except Exception as e:
            logging.error(f"Error scanning port {port}: {e}")

        root.after(0, update_progress)
        port_queue.task_done()

def update_output(text):
    output_box.insert(tk.END, text)
    output_box.see(tk.END)

def update_progress():
    progress['value'] += 1

def start_scan():
    target = target_entry.get().strip()

    if not target:
        messagebox.showerror("Error", "Target cannot be empty")
        return

    try:
        start_port = int(start_entry.get())
        end_port = int(end_entry.get())
        threads = int(thread_entry.get())
        timeout = float(timeout_entry.get())
    except ValueError:
        messagebox.showerror("Error", "Invalid numeric input")
        return

    open_ports.clear()
    output_box.delete(1.0, tk.END)
    progress['value'] = 0

    try:
        ip = socket.gethostbyname(target)
    except:
        messagebox.showerror("Error", "Invalid Host")
        return

    os_guess = detect_os(ip)

    update_output(f"Target: {ip}\n")
    update_output(f"OS Guess: {os_guess}\n\n")

    logging.info(f"Scan started for {ip} | OS Guess: {os_guess}")

    total_ports = end_port - start_port + 1
    progress['maximum'] = total_ports

    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    for _ in range(threads):
        thread = threading.Thread(target=scan_port, args=(ip, timeout))
        thread.daemon = True
        thread.start()

def save_reports():
    if not open_ports:
        messagebox.showwarning("Warning", "No open ports found!")
        return

    with open("scan_report.txt", "w") as f:
        for item in open_ports:
            f.write(f"Port {item['port']} OPEN | Banner: {item['banner']}\n")

    with open("scan_report.json", "w") as f:
        json.dump(open_ports, f, indent=4)

    with open("scan_report.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["port", "banner"])
        writer.writeheader()
        writer.writerows(open_ports)

    messagebox.showinfo("Saved", "Reports saved (TXT, JSON, CSV)")
    logging.info("Reports saved successfully.")

# ================= GUI =================

root = tk.Tk()
root.title("Kali Dark Port Scanner")
root.geometry("900x650")
root.configure(bg="#0f0f0f")

style = ttk.Style()
style.theme_use("clam")

style.configure("TProgressbar",
                troughcolor="#1e1e1e",
                background="#00ff00",
                thickness=15)

title = tk.Label(root,
                 text="PORT SCANNER",
                 bg="#0f0f0f",
                 fg="#00ff00",
                 font=("Courier", 18, "bold"))
title.pack(pady=10)

frame = tk.Frame(root, bg="#0f0f0f")
frame.pack()

def create_label(text):
    return tk.Label(frame, text=text, bg="#0f0f0f",
                    fg="#00ff00", font=("Courier", 10))

def create_entry(default=""):
    e = tk.Entry(frame, bg="#1e1e1e",
                 fg="#00ff00", insertbackground="#00ff00",
                 font=("Courier", 10))
    e.insert(0, default)
    return e

create_label("Target IP/Domain").grid(row=0, column=0)
target_entry = create_entry()
target_entry.grid(row=0, column=1)

create_label("Start Port").grid(row=1, column=0)
start_entry = create_entry("1")
start_entry.grid(row=1, column=1)

create_label("End Port").grid(row=2, column=0)
end_entry = create_entry("1024")
end_entry.grid(row=2, column=1)

create_label("Threads").grid(row=3, column=0)
thread_entry = create_entry("100")
thread_entry.grid(row=3, column=1)

create_label("Timeout").grid(row=4, column=0)
timeout_entry = create_entry("1")
timeout_entry.grid(row=4, column=1)

btn_frame = tk.Frame(root, bg="#0f0f0f")
btn_frame.pack(pady=10)

scan_btn = tk.Button(btn_frame, text="START SCAN",
                     bg="#00ff00", fg="black",
                     font=("Courier", 12, "bold"),
                     command=start_scan)
scan_btn.grid(row=0, column=0, padx=10)

save_btn = tk.Button(btn_frame, text="SAVE REPORT",
                     bg="#ffcc00", fg="black",
                     font=("Courier", 12, "bold"),
                     command=save_reports)
save_btn.grid(row=0, column=1, padx=10)

progress = ttk.Progressbar(root, orient="horizontal",
                           length=800, mode="determinate")
progress.pack(pady=10)

output_box = scrolledtext.ScrolledText(root,
                                       bg="#000000",
                                       fg="#00ff00",
                                       insertbackground="#00ff00",
                                       font=("Courier", 10),
                                       width=110,
                                       height=20)
output_box.pack()

root.mainloop()
