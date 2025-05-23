import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import pandas as pd
import json
import threading
import subprocess
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import os
import re

import matplotlib
matplotlib.use("TkAgg")

# Fichiers
LOG_FILE = "serv/log.txt"
USERS_FILE = "serv/users.json"
BANNED_FILE = "serv/banned_ips.txt"
PHP_COMMAND = ["php", "-S", "localhost:8080"]

class LogAnalyzerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔍 Analyseur de Logs PHP")
        self.geometry("1600x1000")
        self.configure(bg="#1e1e1e")

        self.create_styles()
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill=tk.BOTH, expand=True)

        # Création des onglets
        self.create_logs_tab()
        self.create_admin_tab()
        self.create_security_tab()
        self.create_moderation_tab()
        self.create_webview_tab()

        self.start_php_server()
        self.schedule_refresh()

    def create_styles(self):
        style = ttk.Style()
        style.theme_use('default')
        style.configure("TFrame", background="#2e2e2e")
        style.configure("TLabel", foreground="white", background="#2e2e2e")
        style.configure("TEntry", fieldbackground="#1e1e1e", foreground="white")
        style.configure("TButton", padding=6)
        style.configure("TCombobox", fieldbackground="#1e1e1e", foreground="white")

    def create_logs_tab(self):
        logs_tab = ttk.Frame(self.tabs)
        self.tabs.add(logs_tab, text="📝 Console & Logs")
        logs_tab.columnconfigure(0, weight=1)
        logs_tab.columnconfigure(1, weight=1)
        logs_tab.rowconfigure(0, weight=1)
        logs_tab.rowconfigure(1, weight=1)

        # Console PHP
        self.php_console = scrolledtext.ScrolledText(logs_tab, bg="#121212", fg="lime", insertbackground="white")
        self.php_console.grid(row=0, column=0, sticky="nsew")
        self.php_console.insert(tk.END, "📦 Lancement du serveur PHP...\n")

        # log.txt
        log_frame = ttk.Frame(logs_tab)
        log_frame.grid(row=1, column=0, sticky="nsew")
        self.search_log = ttk.Entry(log_frame)
        self.search_log.pack(fill=tk.X, padx=4, pady=4)
        self.search_log.bind("<KeyRelease>", self.filter_log_text)
        self.log_text = scrolledtext.ScrolledText(log_frame, bg="#121212", fg="white", insertbackground="white")
        self.log_text.pack(expand=True, fill=tk.BOTH, padx=4, pady=4)

        # users.json
        user_frame = ttk.Frame(logs_tab)
        user_frame.grid(row=0, column=1, rowspan=1, sticky="nsew")
        self.search_user = ttk.Entry(user_frame)
        self.search_user.pack(fill=tk.X, padx=4, pady=4)
        self.search_user.bind("<KeyRelease>", self.filter_users_text)
        self.user_text = scrolledtext.ScrolledText(user_frame, bg="#121212", fg="white", insertbackground="white")
        self.user_text.pack(expand=True, fill=tk.BOTH, padx=4, pady=4)

        # Graphique
        graph_frame = ttk.Frame(logs_tab)
        graph_frame.grid(row=1, column=1, sticky="nsew")
        selector_frame = ttk.Frame(graph_frame)
        selector_frame.pack(pady=4)
        self.x_axis = ttk.Combobox(selector_frame, values=["timestamp", "user", "page", "action"])
        self.y_axis = ttk.Combobox(selector_frame, values=["user", "page", "action"])
        self.x_axis.set("timestamp")
        self.y_axis.set("user")
        self.x_axis.pack(side=tk.LEFT, padx=4)
        self.y_axis.pack(side=tk.LEFT, padx=4)
        self.time_range = ttk.Combobox(selector_frame, values=["Tous", "5 minutes", "15 minutes", "1 heure"])
        self.time_range.set("Tous")
        self.time_range.pack(side=tk.LEFT, padx=4)
        ttk.Button(selector_frame, text="Mettre à jour", command=self.update_graph).pack(side=tk.LEFT, padx=4)
        ttk.Button(selector_frame, text="Exporter CSV", command=self.export_csv).pack(side=tk.LEFT, padx=4)
        self.status_label = ttk.Label(graph_frame, text="⏳ En attente des données...")
        self.status_label.pack()
        self.fig, self.ax = plt.subplots(figsize=(6, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(expand=True, fill=tk.BOTH)

    def create_admin_tab(self):
        admin_tab = ttk.Frame(self.tabs)
        self.tabs.add(admin_tab, text="🛠 Admin")
        frame = ttk.Frame(admin_tab)
        frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Ban IP manuel
        ttk.Label(frame, text="🚫 Bannir une IP").pack(anchor="w", pady=4)
        self.ban_ip_entry = ttk.Entry(frame)
        self.ban_ip_entry.pack(fill=tk.X, pady=4)
        ttk.Button(frame, text="Bannir", command=lambda: self.ban_ip_direct(self.ban_ip_entry.get())).pack(pady=4)

        # Débannir manuel
        ttk.Label(frame, text="✅ Débannir une IP").pack(anchor="w", pady=4)
        self.unban_ip_entry = ttk.Entry(frame)
        self.unban_ip_entry.pack(fill=tk.X, pady=4)
        ttk.Button(frame, text="Débannir", command=lambda: self.unban_ip(self.unban_ip_entry.get())).pack(pady=4)

        # Liste IP ban
        self.banned_text = scrolledtext.ScrolledText(frame, height=8, bg="#121212", fg="red")
        self.banned_text.pack(fill=tk.BOTH, pady=4)

        # Rôles
        ttk.Label(frame, text="👑 Définir un rôle").pack(anchor="w", pady=10)
        self.role_user = ttk.Entry(frame)
        self.role_user.pack(fill=tk.X, pady=2)
        self.role_choice = ttk.Combobox(frame, values=["user", "admin"])
        self.role_choice.set("user")
        self.role_choice.pack(fill=tk.X, pady=2)
        ttk.Button(frame, text="Appliquer", command=self.set_user_role).pack(pady=4)

        # Charger bannis
        self.load_banned_ips()

    def create_security_tab(self):
        sec_tab = ttk.Frame(self.tabs)
        self.tabs.add(sec_tab, text="🛡 Sécurité")
        frame = ttk.Frame(sec_tab)
        frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="🚨 IPs suspectes (1 min)").pack(anchor="w", pady=4)
        self.suspicious_list = tk.Listbox(frame, bg="#121212", fg="orange", height=10)
        self.suspicious_list.pack(fill=tk.BOTH, expand=True, pady=4)
        ttk.Button(frame, text="🚫 Bannir auto.", command=self.detect_suspicious_activity).pack(pady=4)

    def create_moderation_tab(self):
        mod_tab = ttk.Frame(self.tabs)
        self.tabs.add(mod_tab, text="📝 Modération")
        ttk.Label(mod_tab, text="Modération à implémenter...", background="#2e2e2e", foreground="white").pack(padx=20, pady=20)

    def create_webview_tab(self):
        web_tab = ttk.Frame(self.tabs)
        self.tabs.add(web_tab, text="🌐 Web View")
        try:
            from tkinterweb import HtmlFrame
            html = HtmlFrame(web_tab, horizontal_scrollbar="auto", messages_enabled=False)
            # Charger directement le site
            html.load_website("http://localhost:8080")
            html.pack(fill=tk.BOTH, expand=True)
        except ImportError:
            try:
                import webview
                btn = ttk.Button(web_tab, text="Ouvrir la webview", command=lambda: webview.create_window('Localhost', 'http://localhost:8080'))
                btn.pack(padx=20, pady=20)
            except ImportError:
                ttk.Label(web_tab, text="Installez tkinterweb ou pywebview", background="#2e2e2e", foreground="white").pack(padx=20, pady=20)
            ttk.Label(web_tab, text="tkinterweb non installé.", background="#2e2e2e", foreground="white").pack(padx=20, pady=20)

    def ban_ip_direct(self, ip):
        if ip and ip not in self.get_banned_ips():
            with open(BANNED_FILE, "a") as f:
                f.write(ip + "\n")
            self.load_banned_ips()

    def unban_ip(self, ip):
        if ip and os.path.exists(BANNED_FILE):
            lines = open(BANNED_FILE).read().splitlines()
            with open(BANNED_FILE, "w") as f:
                for l in lines:
                    if l.strip() != ip:
                        f.write(l + "\n")
            self.load_banned_ips()

    def load_banned_ips(self):
        self.banned_text.delete("1.0", tk.END)
        self.banned_ips = []
        if os.path.exists(BANNED_FILE):
            for ip in open(BANNED_FILE):
                ip = ip.strip()
                if ip:
                    self.banned_ips.append(ip)
                    self.banned_text.insert(tk.END, ip + "\n")

    def get_banned_ips(self):
        return self.banned_ips

    def set_user_role(self):
        user, role = self.role_user.get(), self.role_choice.get()
        try:
            users = json.load(open(USERS_FILE))
            for u in users:
                if u.get("username") == user:
                    u["role"] = role
            with open(USERS_FILE, "w") as f:
                json.dump(users, f, indent=4)
        except Exception as e:
            messagebox.showerror("Erreur rôle", str(e))

    def filter_log_text(self, event=None):
        q = self.search_log.get().lower()
        lines = [l for l in self.log_lines if q in l.lower()]
        self.log_text.delete("1.0", tk.END)
        self.log_text.insert(tk.END, ''.join(lines))

    def filter_users_text(self, event=None):
        q = self.search_user.get().lower()
        lines = [l for l in self.user_lines if q in l.lower()]
        self.user_text.delete("1.0", tk.END)
        self.user_text.insert(tk.END, "\n".join(lines))

    def update_log_and_users(self):
        raw = open(LOG_FILE).read().splitlines()
        self.log_lines = [l + "\n" for l in raw if not any(ip in l for ip in self.banned_ips)]
        self.log_text.delete("1.0", tk.END)
        self.log_text.insert(tk.END, ''.join(self.log_lines))
        users = json.load(open(USERS_FILE))
        self.user_lines = json.dumps(users, indent=4).splitlines()
        self.user_text.delete("1.0", tk.END)
        self.user_text.insert(tk.END, "\n".join(self.user_lines))

    def load_log_df(self, apply_filter=True):
        data = []
        for l in self.log_lines:
            m = re.match(r"\[(.*?)\] IP: (.*?) \| User: (.*?) \| Page: (.*?) \| Action: (.*)", l)
            if m:
                ts, ip, u, p, a = m.groups()
                data.append({
                    "timestamp": datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f"),
                    "ip": ip, "user": u, "page": p, "action": a
                })
        df = pd.DataFrame(data)
        if apply_filter and not df.empty:
            df = df[~df["ip"].isin(self.banned_ips)]
        if not df.empty and self.time_range.get() != "Tous":
            now = datetime.now()
            rng = self.time_range.get()
            if "minute" in rng:
                df = df[df["timestamp"] >= now - timedelta(minutes=int(rng.split()[0]))]
            elif "heure" in rng:
                df = df[df["timestamp"] >= now - timedelta(hours=1)]
        return df

    def update_graph(self):
        try:
            df = self.load_log_df()
            x, y = self.x_axis.get(), self.y_axis.get()
            self.ax.clear()
            if x == "timestamp":
                df["minute"] = df["timestamp"].dt.floor("min"),
                pivot = df.groupby(["minute", y]).size().unstack(fill_value=0)
                pivot.plot(ax=self.ax)
            else:
                pivot = df.groupby([x, y]).size().unstack(fill_value=0)
                pivot.plot(kind="bar", stacked=True, ax=self.ax)
            self.ax.set_title(f"{y} par {x}")
            self.ax.legend(loc='upper right')
            self.canvas.draw()
            self.status_label.config(text=f"✅ {len(df)} entrées analysées.")
        except Exception as e:
            self.ax.clear()
            self.ax.text(0.5, 0.5, f"Erreur : {e}", ha="center", va="center")
            self.canvas.draw()
            self.status_label.config(text="❌ Erreur graphique")

    def detect_suspicious_activity(self):
        df = self.load_log_df(apply_filter=False)
        now = datetime.now()
        last_min = df[df["timestamp"] >= now - timedelta(minutes=1)]
        counts = last_min["ip"].value_counts()
        self.suspicious_list.delete(0, tk.END)
        for ip, cnt in counts.items():
            if cnt >= 20:
                self.ban_ip_direct(ip)
                self.suspicious_list.insert(tk.END, f"{ip} - {cnt} req/min")

    def schedule_refresh(self):
        self.update_log_and_users()
        self.update_graph()
        self.detect_suspicious_activity()
        self.load_banned_ips()
        self.after(5000, self.schedule_refresh)

    def export_csv(self):
        df = self.load_log_df()
        path = filedialog.asksaveasfilename(defaultextension='.csv')
        if path:
            df.to_csv(path, index=False)
            self.status_label.config(text=f"📁 Exporté vers : {path}")

    def start_php_server(self):
        def run():
            proc = subprocess.Popen(PHP_COMMAND, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in proc.stdout:
                self.php_console.insert(tk.END, line)
                self.php_console.see(tk.END)
        threading.Thread(target=run, daemon=True).start()

if __name__ == '__main__':
    LogAnalyzerApp().mainloop()
