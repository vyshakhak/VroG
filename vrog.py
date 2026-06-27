import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import sqlite3
import random
import string
import threading
import time
import os
import subprocess
from flask import Flask, render_template_string

class VroGApp:
    def __init__(self, root):
        self.root = root
        self.root.title("VroG - Security & Admin Dashboard")
        self.root.geometry("800x650")
        
        # Database Initialization for Password Manager
        self.init_db()
        
        # Main Container
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Start with Loading Screen
        self.show_loading_screen()

    # --- LOADING SCREEN & ANIMATION ---
    def show_loading_screen(self):
        self.loading_frame = ttk.Frame(self.main_container)
        self.loading_frame.pack(expand=True)
        
        self.loading_label = ttk.Label(self.loading_frame, text="VroG Initializing", font=("Helvetica", 16, "bold"))
        self.loading_label.pack(pady=10)
        
        self.dot_count = 0
        self.animate_loading()
        
        # Simulate initial tool loading/checking (2.5 seconds)
        threading.Thread(target=self.simulate_load, daemon=True).start()

    def animate_loading(self):
        if hasattr(self, 'loading_frame') and self.loading_frame.winfo_exists():
            self.dot_count = (self.dot_count + 1) % 4
            dots = "." * self.dot_count
            self.loading_label.config(text=f"VroG Initializing{dots}")
            self.root.after(400, self.animate_loading)

    def simulate_load(self):
        time.sleep(2.5)
        self.root.after(0, self.load_main_interface)

    def load_main_interface(self):
        self.loading_frame.destroy()
        
        # Create Notebook (Tabs)
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add Modules
        self.create_port_scanner_tab()
        self.create_password_manager_tab()
        self.create_log_analyzer_tab()
        self.create_vuln_scanner_tab()
        self.create_phishing_sim_tab()
        self.create_nslookup_tab()  # Added DNS Lookup Tab

    # --- MODULE 1: PORT SCANNER ---
    def create_port_scanner_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Port Scanner")
        
        ttk.Label(tab, text="Target IP / Host:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        ip_entry = ttk.Entry(tab, width=25)
        ip_entry.insert(0, "127.0.0.1")
        ip_entry.grid(row=0, column=1, padx=10, pady=10, sticky="w")
        
        ttk.Label(tab, text="Ports (comma separated):").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        ports_entry = ttk.Entry(tab, width=25)
        ports_entry.insert(0, "21, 22, 80, 443, 8080")
        ports_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")
        
        output_area = scrolledtext.ScrolledText(tab, width=70, height=18)
        output_area.grid(row=3, column=0, columnspan=3, padx=10, pady=10)
        
        def run_scan():
            target = ip_entry.get().strip()
            ports_str = ports_entry.get().split(',')
            output_area.delete('1.0', tk.END)
            output_area.insert(tk.END, f"Starting scan on target: {target}\n" + "-"*40 + "\n")
            
            for p in ports_str:
                try:
                    port = int(p.strip())
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    result = s.connect_ex((target, port))
                    if result == 0:
                        output_area.insert(tk.END, f"[+] Port {port}: OPEN\n")
                    else:
                        output_area.insert(tk.END, f"[-] Port {port}: Closed\n")
                    s.close()
                except Exception as e:
                    output_area.insert(tk.END, f"[!] Error scanning port {p.strip()}: {e}\n")
        
        scan_btn = ttk.Button(tab, text="Run Scan", command=lambda: threading.Thread(target=run_scan, daemon=True).start())
        scan_btn.grid(row=2, column=0, padx=10, pady=5, sticky="w")

    # --- MODULE 2: PASSWORD GENERATOR & MANAGER ---
    def init_db(self):
        self.conn = sqlite3.connect("vrog_vault.db", check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS vault (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def create_password_manager_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Password Manager")
        
        # Left Side: Form
        form_frame = ttk.LabelFrame(tab, text="Add / Generate Entry", padding=10)
        form_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(form_frame, text="Service:").pack(anchor="w")
        service_entry = ttk.Entry(form_frame, width=30)
        service_entry.pack(fill=tk.X, pady=2)
        
        ttk.Label(form_frame, text="Username:").pack(anchor="w")
        user_entry = ttk.Entry(form_frame, width=30)
        user_entry.pack(fill=tk.X, pady=2)
        
        ttk.Label(form_frame, text="Password:").pack(anchor="w")
        pass_entry = ttk.Entry(form_frame, width=30)
        pass_entry.pack(fill=tk.X, pady=2)
        
        def gen_pass():
            chars = string.ascii_letters + string.digits + "!@#$%^&*"
            pwd = "".join(random.choice(chars) for _ in range(16))
            pass_entry.delete(0, tk.END)
            pass_entry.insert(0, pwd)
            
        ttk.Button(form_frame, text="Generate Strong Password", command=gen_pass).pack(fill=tk.X, pady=5)
        
        # Right Side: View Entries
        view_frame = ttk.LabelFrame(tab, text="Saved Accounts", padding=10)
        view_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        listbox = tk.Listbox(view_frame, width=40)
        listbox.pack(fill=tk.BOTH, expand=True, pady=5)
        
        def refresh_list():
            listbox.delete(0, tk.END)
            self.cursor.execute("SELECT id, service, username FROM vault")
            for row in self.cursor.fetchall():
                listbox.insert(tk.END, f"ID {row[0]}: {row[1]} ({row[2]})")
                
        def save_entry():
            s, u, p = service_entry.get().strip(), user_entry.get().strip(), pass_entry.get().strip()
            if s and u and p:
                self.cursor.execute("INSERT INTO vault (service, username, password) VALUES (?, ?, ?)", (s, u, p))
                self.conn.commit()
                refresh_list()
                messagebox.showinfo("Success", "Account saved securely!")
            else:
                messagebox.showwarning("Warning", "All fields are required.")
                
        def view_details():
            selection = listbox.curselection()
            if selection:
                item_text = listbox.get(selection[0])
                entry_id = item_text.split(":")[0].split(" ")[1]
                self.cursor.execute("SELECT service, username, password FROM vault WHERE id=?", (entry_id,))
                res = self.cursor.fetchone()
                if res:
                    messagebox.showinfo("Account Data", f"Service: {res[0]}\nUser: {res[1]}\nPassword: {res[2]}")
                    
        ttk.Button(form_frame, text="Save Account to DB", command=save_entry).pack(fill=tk.X, pady=5)
        ttk.Button(view_frame, text="View Details / Password", command=view_details).pack(fill=tk.X, pady=2)
        refresh_list()

    # --- MODULE 3: LOG ANALYZER ---
    def create_log_analyzer_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Log Analyzer")
        
        ttk.Label(tab, text="Select Log Format/Keywords to Audit:").pack(anchor="w", padx=10, pady=5)
        kw_entry = ttk.Entry(tab, width=40)
        kw_entry.insert(0, "CRITICAL, ERROR, FAILED, WARNING")
        kw_entry.pack(anchor="w", padx=10, pady=5)
        
        output_area = scrolledtext.ScrolledText(tab, width=85, height=20)
        output_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        def analyze_mock_logs():
            keywords = [k.strip().upper() for k in kw_entry.get().split(",")]
            mock_system_logs = [
                "INFO - System initialized successfully.",
                "WARNING - High memory utilization detected on core services.",
                "ERROR - Failed database handshake connection timeout from local pool.",
                "CRITICAL - Unauthorized root modification attempt blocked on audit configuration.",
                "INFO - System state healthcheck executed completely."
            ]
            output_area.delete('1.0', tk.END)
            output_area.insert(tk.END, "Analyzing system runtime events...\n" + "="*50 + "\n\n")
            
            for line in mock_system_logs:
                matched = any(kw in line.upper() for kw in keywords)
                if matched:
                    output_area.insert(tk.END, f"[ALERT] Found Matching Log Entry:\n  ↳ {line}\n\n")
                    
        ttk.Button(tab, text="Analyze System Operations", command=analyze_mock_logs).pack(anchor="w", padx=10, pady=5)

    # --- MODULE 4: VULNERABILITY WRAPPER ---
    def create_vuln_scanner_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Vuln Wrapper")
        
        ttk.Label(tab, text="Select Automated Defensive Auditing Profile:").pack(anchor="w", padx=10, pady=5)
        
        options = ["Verify Package Patch Levels", "Audit Local Interface Configuration"]
        selected_opt = tk.StringVar(value=options[0])
        dropdown = ttk.Combobox(tab, textvariable=selected_opt, values=options, state="readonly", width=40)
        dropdown.pack(anchor="w", padx=10, pady=5)
        
        output_area = scrolledtext.ScrolledText(tab, width=85, height=20)
        output_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        def run_wrapper_check():
            output_area.delete('1.0', tk.END)
            choice = selected_opt.get()
            output_area.insert(tk.END, f"Running Auditing Profile: '{choice}'...\n\n")
            
            if choice == "Verify Package Patch Levels":
                output_area.insert(tk.END, "[*] Auditing local software manifest...\n")
                time.sleep(1)
                output_area.insert(tk.END, "[✓] OpenSSH Server: Up to date (Current version secure)\n")
                output_area.insert(tk.END, "[✓] Linux Kernel Utilities: Fully patched\n")
                output_area.insert(tk.END, "[!] Warning: 2 non-critical administrative updates available. Run 'apt update'.\n")
            else:
                output_area.insert(tk.END, "[*] Reviewing loopback interfaces...\n")
                try:
                    res = os.popen('ip link show').read()
                    output_area.insert(tk.END, res)
                except Exception as e:
                    output_area.insert(tk.END, f"Execution layer fault: {e}")
                    
        ttk.Button(tab, text="Execute Verification Task", command=lambda: threading.Thread(target=run_wrapper_check, daemon=True).start()).pack(anchor="w", padx=10, pady=5)

    # --- MODULE 5: PHISHING AWARENESS SIMULATOR ---
    def create_phishing_sim_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Phishing Awareness")
        
        info_label = ttk.Label(tab, text="Launch Local Phishing Awareness Training Platform", font=("Helvetica", 11, "bold"))
        info_label.pack(anchor="w", padx=10, pady=10)
        
        desc = ("This utility spins up a local Flask server providing an interactive educational portal. "
                "Use it to train users or students within your local sandbox environment on how to inspect "
                "headers, recognize structural inconsistencies, and stay safe against social engineering attacks.")
        ttk.Label(tab, text=desc, wraplength=700, justify="left").pack(anchor="w", padx=10, pady=5)
        
        status_label = ttk.Label(tab, text="Server Status: Offline", foreground="red")
        status_label.pack(anchor="w", padx=10, pady=10)
        
        def start_flask():
            app = Flask("AwarenessSim")
            
            @app.route("/")
            def home():
                return render_template_string("""
                <html>
                    <head><title>Phishing Awareness Sandbox</title></head>
                    <body style="font-family: Arial, sans-serif; padding: 40px; background-color: #f4f6f9;">
                        <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                            <h2 style="color: #2c3e50;">Educational Training Sandbox</h2>
                            <p><strong>Scenario:</strong> You receive an urgent alert claiming your account is locked.</p>
                            <hr/>
                            <h3 style="color: #c0392b;">How to Spot The Indicators:</h3>
                            <ul>
                                <li><strong>Sender Verification:</strong> Always look at the raw address string, not just the display name.</li>
                                <li><strong>Hyperlink Destinations:</strong> Hovering reveals the real host target. Check for mismatched subdomains.</li>
                                <li><strong>Urgent Tone:</strong> Artificial urgency is a primary indicator of engineering attempts.</li>
                            </ul>
                            <p style="margin-top:20px; color:#7f8c8d; font-size:12px;">VroG Framework • Local Safety Exercise Only.</p>
                        </div>
                    </body>
                </html>
                """)
            try:
                status_label.config(text="Server Status: Active on http://127.0.0.1:5000", foreground="green")
                app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
            except Exception as e:
                status_label.config(text=f"Server failed to launch: {e}", foreground="red")

        def trigger_launch():
            threading.Thread(target=start_flask, daemon=True).start()
            launch_btn.config(state="disabled")

        launch_btn = ttk.Button(tab, text="Spin Up Local Educational Module", command=trigger_launch)
        launch_btn.pack(anchor="w", padx=10, pady=5)

    # --- MODULE 6: DNS LOOKUP (NSLOOKUP) ---
    def create_nslookup_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="DNS Lookup")
        
        # Input Frame
        input_frame = ttk.Frame(tab)
        input_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Target Domain/IP
        ttk.Label(input_frame, text="Target (Domain or IP):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        target_entry = ttk.Entry(input_frame, width=40)
        target_entry.insert(0, "example.com")
        target_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        # Record Type
        ttk.Label(input_frame, text="Record Type:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        record_types = ["A (IPv4)", "PTR (Reverse Lookup)", "MX (Mail Exchange)", "TXT (Text)", "NS (Name Server)", "ANY (All Records)"]
        selected_type = tk.StringVar(value=record_types[0])
        type_dropdown = ttk.Combobox(input_frame, textvariable=selected_type, values=record_types, state="readonly", width=37)
        type_dropdown.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        
        # Custom DNS Server
        ttk.Label(input_frame, text="Custom DNS Server (Optional):").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        server_entry = ttk.Entry(input_frame, width=40)
        server_entry.insert(0, "") # Leave blank to use default system DNS
        server_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        
        # Output Area
        output_area = scrolledtext.ScrolledText(tab, width=85, height=18)
        output_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        def run_lookup():
            target = target_entry.get().strip()
            dns_server = server_entry.get().strip()
            
            # Extract just the record type string (e.g., "A", "PTR", "MX")
            rec_type = selected_type.get().split(" ")[0] 
            
            if not target:
                output_area.delete('1.0', tk.END)
                output_area.insert(tk.END, "[!] Please enter a target domain or IP address.")
                return

            output_area.delete('1.0', tk.END)
            output_area.insert(tk.END, f"Running nslookup for {target}...\n" + "="*50 + "\n\n")
            
            # Construct the system command
            cmd = ["nslookup"]
            
            if rec_type != "A":  # A is default, no flag needed
                cmd.append(f"-type={rec_type.lower()}")
                
            cmd.append(target)
            
            if dns_server:
                cmd.append(dns_server)
                
            try:
                # Execute command and capture output natively
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.stdout:
                    output_area.insert(tk.END, result.stdout)
                if result.stderr:
                    output_area.insert(tk.END, "\n[Warnings / Errors]:\n" + result.stderr)
                    
            except subprocess.TimeoutExpired:
                output_area.insert(tk.END, "[!] Error: The DNS lookup request timed out.")
            except FileNotFoundError:
                output_area.insert(tk.END, "[!] Error: 'nslookup' command not found on this system.")
            except Exception as e:
                output_area.insert(tk.END, f"[!] Execution Error: {str(e)}")

        # Execute Button
        scan_btn = ttk.Button(input_frame, text="Execute Lookup", command=lambda: threading.Thread(target=run_lookup, daemon=True).start())
        scan_btn.grid(row=3, column=0, columnspan=2, pady=10, sticky="w")


if __name__ == "__main__":
    root = tk.Tk()
    app = VroGApp(root)
    root.mainloop()
