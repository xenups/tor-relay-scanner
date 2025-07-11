import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import subprocess
import threading
import os
import sys
import asyncio
import aiohttp
import random

# ---------------------------
# Tor Relay Scanner Tab
# ---------------------------

COUNTRIES = [
    "US", "GB", "DE", "NL", "FR", "SE", "RU", "TR", "IR", "CN",
    "UA", "CA", "PL", "IN", "BR", "AU", "CH", "IT", "ES", "JP"
]

class TorRelayScannerTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.entries = {}
        self.selected_countries = []

        # Input fields
        self.add_entry("Number of Relays (-n):", "30", "num_relays")
        self.add_entry("Goal Working Relays (--goal):", "5", "goal")
        self.add_entry("Timeout (seconds):", "10", "timeout")
        self.add_entry("Ports (-p, comma-separated):", "", "ports")
        self.add_entry("Output File Path (-o):", "", "outfile", button_label="Browse", browse=True)

        # Country selection combobox
        self.country_combo = ttk.Combobox(self, values=COUNTRIES, state="readonly")
        self.country_combo.pack(padx=10, pady=(5, 2), fill="x")
        self.country_combo.bind("<<ComboboxSelected>>", self.add_country)

        # Frame to hold selected country labels
        self.countries_frame = tk.Frame(self)
        self.countries_frame.pack(padx=10, pady=(0, 10), fill="x")

        # torrc format checkbox
        self.torrc_var = tk.BooleanVar()
        tk.Checkbutton(self, text="Output in torrc format (--torrc)", variable=self.torrc_var).pack(anchor="w", padx=10)

        # Start scan button
        self.start_btn = tk.Button(self, text="Start Scan", command=self.start_scan)
        self.start_btn.pack(pady=10)

        # Split output area: left = results, right = logs (stacked vertically with titles)
        out_frame = tk.Frame(self)
        out_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # Results Label
        tk.Label(out_frame, text="Results:").pack(anchor="w")
        self.results_box = scrolledtext.ScrolledText(out_frame, height=12, width=80, state="disabled")
        self.results_box.pack(fill="both", expand=True, padx=(0, 5), pady=(0, 10))

        # Logs Label
        tk.Label(out_frame, text="Logs:").pack(anchor="w")
        self.log_box = scrolledtext.ScrolledText(out_frame, height=12, width=80, state="disabled")
        self.log_box.pack(fill="both", expand=True)

        self.log("Ready.\n")

    def add_entry(self, label, default, key, button_label=None, browse=False):
        frame = tk.Frame(self)
        frame.pack(padx=10, pady=2, fill="x")
        tk.Label(frame, text=label).pack(side="left")
        entry = tk.Entry(frame)
        entry.insert(0, default)
        entry.pack(side="left", fill="x", expand=True, padx=5)
        self.entries[key] = entry
        if browse:
            btn = tk.Button(frame, text=button_label, command=self.browse_output)
            btn.pack(side="left")

    def browse_output(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if path:
            self.entries["outfile"].delete(0, tk.END)
            self.entries["outfile"].insert(0, path)

    def add_country(self, event=None):
        code = self.country_combo.get().upper()
        if code in self.selected_countries:
            return
        self.selected_countries.append(code)

        frame = tk.Frame(self.countries_frame)
        frame.pack(side="left", padx=5)

        lbl = tk.Label(frame, text=code, relief="solid", padx=5)
        lbl.pack(side="left")

        btn = tk.Button(frame, text="×", command=lambda: self.remove_country(code, frame), width=2)
        btn.pack(side="left")

    def remove_country(self, code, frame):
        if code in self.selected_countries:
            self.selected_countries.remove(code)
        frame.destroy()

    def build_command(self):
        scanner_path = os.path.join("src", "tor_relay_scanner", "scanner.py")
        scanner_path = os.path.abspath(scanner_path)

        cmd = [sys.executable, scanner_path]
        cmd += ["-n", self.entries["num_relays"].get()]
        cmd += ["--goal", self.entries["goal"].get()]
        cmd += ["--timeout", self.entries["timeout"].get()]

        if self.selected_countries:
            cmd += ["-c", ",".join(c.lower() for c in self.selected_countries)]

        ports = self.entries["ports"].get()
        if ports:
            for p in ports.split(","):
                cmd += ["-p", p.strip()]

        if self.entries["outfile"].get():
            cmd += ["-o", self.entries["outfile"].get()]

        if self.torrc_var.get():
            cmd.append("--torrc")

        return cmd

    def start_scan(self):
        self.start_btn.config(state="disabled")
        self.set_results_text("")
        self.set_log_text("")
        self.log("Starting scan...\n")
        cmd = self.build_command()
        threading.Thread(target=self.run_scan, args=(cmd,), daemon=True).start()

    def run_scan(self, cmd):
        try:
            self.log(f"\n[DEBUG] Running command: {' '.join(cmd)}\n\n")
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

            capture_results = False
            capture_all_reachable = False

            for line in process.stdout:
                line = line.rstrip("\n")

                # Filter relay blocks
                if line.strip() == "The following relays are reachable this test attempt:":
                    capture_results = True
                    continue

                if line.strip() == "All reachable relays:":
                    capture_all_reachable = True
                    continue

                if capture_results:
                    if line.strip() == "":
                        capture_results = False
                    elif self.is_relay_line(line):
                        self.append_results(line + "\n")
                    else:
                        capture_results = False

                elif capture_all_reachable:
                    if line.strip() == "":
                        capture_all_reachable = False
                    elif self.is_relay_line(line):
                        self.append_results(line + "\n")
                    else:
                        capture_all_reachable = False

                else:
                    self.log(line + "\n")

            returncode = process.wait()
            self.log(f"\n[INFO] Scan completed with exit code {returncode}\n")
        except Exception as e:
            self.log(f"[ERROR] {e}\n")
        finally:
            self.start_btn.config(state="normal")

    def is_relay_line(self, line):
        parts = line.split()
        if len(parts) != 2:
            return False
        ip_port, fingerprint = parts
        if ":" not in ip_port:
            return False
        if len(fingerprint) != 40:
            return False
        if not all(c in "0123456789ABCDEFabcdef" for c in fingerprint):
            return False
        return True

    def log(self, msg):
        self.log_box.config(state="normal")
        self.log_box.insert(tk.END, msg)
        self.log_box.see(tk.END)
        self.log_box.config(state="disabled")

    def append_results(self, msg):
        self.results_box.config(state="normal")
        self.results_box.insert(tk.END, msg)
        self.results_box.see(tk.END)
        self.results_box.config(state="disabled")

    def set_results_text(self, text):
        self.results_box.config(state="normal")
        self.results_box.delete("1.0", tk.END)
        self.results_box.insert(tk.END, text)
        self.results_box.config(state="disabled")

    def set_log_text(self, text):
        self.log_box.config(state="normal")
        self.log_box.delete("1.0", tk.END)
        self.log_box.insert(tk.END, text)
        self.log_box.config(state="disabled")

# ---------------------------
# Bridge Scanner Tab
# ---------------------------

URLS = {
    "obfs4": "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/refs/heads/main/bridges-obfs4",
    "webtunnel": "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/refs/heads/main/bridges-webtunnel",
}


class BridgeScannerTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        self.mode_var = tk.StringVar(value="obfs4")
        self.count_var = tk.StringVar(value="10")

        self.create_widgets()

    def create_widgets(self):
        frame = ttk.Frame(self, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Bridge Type:").grid(row=0, column=0, sticky="w")
        ttk.OptionMenu(frame, self.mode_var, "obfs4", "obfs4", "webtunnel").grid(
            row=0, column=1, sticky="w"
        )

        ttk.Label(frame, text="Max Results:").grid(row=1, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.count_var).grid(row=1, column=1, sticky="w")

        ttk.Button(frame, text="Start Scan", command=self.start_scan).grid(
            row=2, column=0, columnspan=2, pady=10
        )

        self.result_box = tk.Text(frame, wrap="none", height=20)
        self.result_box.grid(row=3, column=0, columnspan=2, sticky="nsew")

        frame.rowconfigure(3, weight=1)
        frame.columnconfigure(1, weight=1)

    def start_scan(self):
        try:
            count = int(self.count_var.get())
            if count <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror(
                "Invalid Input", "Max Results must be a positive integer."
            )
            return

        self.result_box.delete("1.0", tk.END)
        self.result_box.insert(tk.END, "🔍 Scanning, please wait...\n")

        threading.Thread(
            target=self.run_scan_async, args=(self.mode_var.get(), count), daemon=True
        ).start()

    def run_scan_async(self, mode, max_results):
        asyncio.run(self.scan(mode, max_results))

    async def fetch_bridge_list(self, url):
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                text = await resp.text()
                return text.strip().splitlines()

    def normalize_ip(self, ip: str, port: str):
        if ":" in ip and not ip.startswith("["):
            ip = f"[{ip}]"
        return ip, port

    async def check_tcp(self, ip: str, port: int, timeout: float = 4.0):
        ip, port_str = self.normalize_ip(ip, str(port))
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            print(f"✅ Connection succeeded to {ip}:{port}")
            return True
        except Exception as e:
            print(f"❌ Connection failed to {ip}:{port} -> {e}")
            return False

    async def scan(self, mode, max_success):
        bridges = await self.fetch_bridge_list(URLS[mode])
        random.shuffle(bridges)

        found = []
        tasks = []

        for line in bridges:
            if len(found) >= max_success:
                break
            parts = line.split()
            if len(parts) < 2 or ":" not in parts[1]:
                continue
            ip, port = self.split_host_port(parts[1])

            tasks.append((asyncio.create_task(self.check_tcp(ip, int(port))), line))

            if len(tasks) >= 1000:
                results = await asyncio.gather(*[t[0] for t in tasks])
                for result, (_, line_text) in zip(results, tasks):
                    if result and len(found) < max_success:
                        found.append(line_text)
                tasks = []

        if tasks and len(found) < max_success:
            results = await asyncio.gather(*[t[0] for t in tasks])
            for result, (_, line_text) in zip(results, tasks):
                if result and len(found) < max_success:
                    found.append(line_text)

        self.after(0, self.show_results, found)

    def show_results(self, bridges):
        self.result_box.delete("1.0", tk.END)
        if not bridges:
            self.result_box.insert(tk.END, "❌ No reachable bridges found.\n")
        else:
            self.result_box.insert(tk.END, "✅ Found reachable bridges:\n\n")
            for b in bridges:
                self.result_box.insert(tk.END, b + "\n")

    def split_host_port(self, addr: str):
        addr = addr.strip()
        if addr.startswith("["):
            host_end = addr.find("]")
            ip = addr[1:host_end]
            port = addr[host_end + 2 :]
        else:
            parts = addr.rsplit(":", 1)
            if len(parts) != 2:
                raise ValueError(f"Invalid address format: {addr}")
            ip, port = parts
        return ip, port


# ---------------------------
# Main Application Window
# ---------------------------

class MainApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Tor Relay and Bridge Scanner")
        self.geometry("900x700")

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)

        # Add tabs
        self.relay_tab = TorRelayScannerTab(self.notebook)
        self.notebook.add(self.relay_tab, text="Relay Scanner")

        self.bridge_tab = BridgeScannerTab(self.notebook)
        self.notebook.add(self.bridge_tab, text="Bridge Scanner")


def main():
    app = MainApp()
    app.mainloop()


if __name__ == "__main__":
    main()
