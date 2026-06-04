#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Сервер политики СПО защищённого канала — GUI версия."""

import os
import sys
import json
import time
import threading
import queue
import socket
import ssl
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import GuiLogger, TLSEngine, TelemetryCollector, PolicyEngine

RULES_TEXT = """╔══════════════════════════════════════════════════════════════════╗
║              ПРАВИЛА ПОЛЬЗОВАНИЯ СЕРВЕРОМ ПОЛИТИКИ              ║
╠══════════════════════════════════════════════════════════════════╣
1. Сервер политики — критический компонент Zero Trust.
2. Запускайте только в защищённом сегменте (DMZ).
3. Убедитесь, что сертификаты не просрочены и порт открыт.
4. Все подключения требуют mTLS.
5. Не передавайте приватный ключ сервера третьим лицам.
╚══════════════════════════════════════════════════════════════════╝"""

HELP_TEXT = """ИНСТРУКЦИЯ ПО ПРИМЕНЕНИЮ (Сервер политики)
1. ПОДГОТОВКА: укажите пути к CA, server.crt, server.key.
2. ПОРТ: по умолчанию 8443. Убедитесь, что порт свободен.
3. ПОЛИТИКИ: настройте лимиты CPU, требование антивируса.
4. ЗАПУСК: нажмите «Запустить сервер».
5. МОНИТОРИНГ: вкладка «Клиенты» показывает активные соединения.
6. СБОРКА .EXE: pyinstaller --windowed --onefile server_gui.py"""

class ServerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("СПО Защищённый канал — Сервер политики (Zero Trust)")
        self.root.geometry("1000x750")
        self.log_queue = queue.Queue()
        self.logger = GuiLogger(self.log_queue)
        self.running = False
        self.stop_event = threading.Event()
        self.server_thread = None
        self.clients_lock = threading.Lock()
        self.clients: dict = {}
        self.policy = PolicyEngine()
        self._build_ui()
        self._process_log_queue()
        self._show_rules_on_first_run()

    def _build_ui(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Правила пользования", command=self._show_rules)
        help_menu.add_command(label="Инструкция", command=self._show_help)
        help_menu.add_command(label="О программе", command=self._show_about)
        menubar.add_cascade(label="Справка", menu=help_menu)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Главная
        tab_main = ttk.Frame(self.notebook)
        self.notebook.add(tab_main, text="  Главная  ")
        ind_frame = ttk.LabelFrame(tab_main, text="Статус сервера")
        ind_frame.pack(fill=tk.X, padx=10, pady=10)
        self.ind_server = tk.Label(ind_frame, text=" Сервер: остановлен ", bg="red", fg="white", font=("Arial", 12, "bold"))
        self.ind_server.pack(side=tk.LEFT, padx=5, pady=5)
        self.ind_tls = tk.Label(ind_frame, text=" TLS: неактивен ", bg="gray", fg="white", font=("Arial", 12, "bold"))
        self.ind_tls.pack(side=tk.LEFT, padx=5, pady=5)
        self.ind_clients = tk.Label(ind_frame, text=" Клиентов: 0 ", bg="gray", fg="white", font=("Arial", 12, "bold"))
        self.ind_clients.pack(side=tk.LEFT, padx=5, pady=5)

        btn_frame = ttk.Frame(tab_main)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        self.btn_start = ttk.Button(btn_frame, text="Запустить сервер", command=self._start_server, width=20)
        self.btn_start.pack(side=tk.LEFT, padx=5)
        self.btn_stop = ttk.Button(btn_frame, text="Остановить", command=self._stop_server, width=20, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Показать правила", command=self._show_rules).pack(side=tk.RIGHT, padx=5)

        info_frame = ttk.LabelFrame(tab_main, text="Системная информация")
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.info_text = scrolledtext.ScrolledText(info_frame, wrap=tk.WORD, state=tk.DISABLED, height=8)
        self.info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Конфигурация
        tab_cfg = ttk.Frame(self.notebook)
        self.notebook.add(tab_cfg, text=" Конфигурация ")
        cfg_frame = ttk.Frame(tab_cfg)
        cfg_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(cfg_frame, text="Порт:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=3)
        self.port_var = tk.StringVar(value="8443")
        ttk.Entry(cfg_frame, textvariable=self.port_var, width=10).grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Label(cfg_frame, text="Адрес прослушивания:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=3)
        self.host_var = tk.StringVar(value="0.0.0.0")
        ttk.Entry(cfg_frame, textvariable=self.host_var, width=15).grid(row=1, column=1, sticky=tk.W, padx=5)

        cert_frame = ttk.LabelFrame(tab_cfg, text="Сертификаты X.509")
        cert_frame.pack(fill=tk.X, padx=10, pady=10)
        self.cert_vars = {}
        certs = [("CA сертификат", "ca_cert", "certs/ca.crt"), ("Сервер cert", "server_cert", "certs/server.crt"), ("Сервер key", "server_key", "certs/server.key")]
        for i, (label, key, default) in enumerate(certs):
            ttk.Label(cert_frame, text=label).grid(row=i, column=0, sticky=tk.W, padx=5, pady=3)
            var = tk.StringVar(value=default)
            self.cert_vars[key] = var
            ttk.Entry(cert_frame, textvariable=var, width=45).grid(row=i, column=1, sticky=tk.W, padx=5)
            ttk.Button(cert_frame, text="Обзор...", command=lambda v=var: self._browse(v)).grid(row=i, column=2, padx=5)
        ttk.Button(tab_cfg, text="Создать тестовые сертификаты", command=self._gen_certs).pack(anchor=tk.W, padx=10, pady=10)

        # Политики
        tab_pol = ttk.Frame(self.notebook)
        self.notebook.add(tab_pol, text="  Политики  ")
        pol_frame = ttk.LabelFrame(tab_pol, text="Правила Zero Trust")
        pol_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(pol_frame, text="Макс. загрузка CPU (%):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.max_cpu_var = tk.StringVar(value="95")
        ttk.Spinbox(pol_frame, from_=10, to=100, textvariable=self.max_cpu_var, width=5).grid(row=0, column=1, sticky=tk.W, padx=5)
        self.av_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(pol_frame, text="Требовать наличие антивируса", variable=self.av_var).grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
        ttk.Button(tab_pol, text="Сохранить политики", command=self._save_policies).pack(anchor=tk.W, padx=10, pady=10)

        # Клиенты
        tab_cli = ttk.Frame(self.notebook)
        self.notebook.add(tab_cli, text="  Клиенты  ")
        cols = ("IP", "Устройство", "CPU%", "Память%", "Антивирус", "Статус", "Подключён")
        self.tree = ttk.Treeview(tab_cli, columns=cols, show="headings", height=12)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=120, anchor=tk.CENTER)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        ttk.Button(tab_cli, text="Обновить список", command=self._refresh_clients).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(tab_cli, text="Отключить выбранного", command=self._kick_client).pack(side=tk.LEFT, padx=5, pady=5)

        # Логи
        tab_logs = ttk.Frame(self.notebook)
        self.notebook.add(tab_logs, text="  Логи  ")
        self.log_text = scrolledtext.ScrolledText(tab_logs, wrap=tk.WORD, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        ttk.Button(tab_logs, text="Очистить", command=self._clear_logs).pack(anchor=tk.E, padx=5, pady=5)

        # Справка
        tab_help = ttk.Frame(self.notebook)
        self.notebook.add(tab_help, text="  Справка  ")
        txt = scrolledtext.ScrolledText(tab_help, wrap=tk.WORD, state=tk.DISABLED)
        txt.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        txt.config(state=tk.NORMAL)
        txt.insert(tk.END, RULES_TEXT + "\n\n" + HELP_TEXT)
        txt.config(state=tk.DISABLED)

    def _browse(self, var):
        p = filedialog.askopenfilename(filetypes=[("PEM/CRT/KEY", "*.pem *.crt *.key"), ("All", "*.*")])
        if p:
            var.set(p)

    def _gen_certs(self):
        import subprocess
        os.makedirs("certs", exist_ok=True)
        cmds = [
            'openssl req -x509 -newkey rsa:2048 -keyout certs/ca.key -out certs/ca.crt -days 365 -nodes -subj "/CN=Test-CA"',
            'openssl req -newkey rsa:2048 -keyout certs/server.key -out certs/server.csr -nodes -subj "/CN=localhost"',
            'openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/server.crt -days 365'
        ]
        for c in cmds:
            subprocess.run(c, shell=True, capture_output=True)
        self.cert_vars["ca_cert"].set(os.path.abspath("certs/ca.crt"))
        self.cert_vars["server_cert"].set(os.path.abspath("certs/server.crt"))
        self.cert_vars["server_key"].set(os.path.abspath("certs/server.key"))
        messagebox.showinfo("Готово", "Тестовые сертификаты созданы в папке certs/")

    def _save_policies(self):
        self.policy.rules["max_cpu"] = float(self.max_cpu_var.get())
        self.policy.rules["antivirus_required"] = self.av_var.get()
        messagebox.showinfo("Сохранено", "Политики Zero Trust обновлены")

    def _show_rules(self):
        win = tk.Toplevel(self.root)
        win.title("Правила пользования")
        win.geometry("600x500")
        t = scrolledtext.ScrolledText(win, wrap=tk.WORD)
        t.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        t.insert(tk.END, RULES_TEXT)
        t.config(state=tk.DISABLED)
        ttk.Button(win, text="Закрыть", command=win.destroy).pack(pady=5)

    def _show_help(self):
        win = tk.Toplevel(self.root)
        win.title("Инструкция")
        win.geometry("700x600")
        t = scrolledtext.ScrolledText(win, wrap=tk.WORD)
        t.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        t.insert(tk.END, HELP_TEXT)
        t.config(state=tk.DISABLED)
        ttk.Button(win, text="Закрыть", command=win.destroy).pack(pady=5)

    def _show_about(self):
        messagebox.showinfo("О программе", "СПО Сервер политики Zero Trust\nВерсия: 1.0 (GUI)\nТехнологии: Python 3, TLS 1.3, mTLS, Zero Trust\nАвтор: Котомин С.М.\nВОРЭ (г. Череповец)")

    def _show_rules_on_first_run(self):
        flag = ".server_rules_accepted"
        if not os.path.exists(flag):
            if messagebox.askyesno("Правила пользования", RULES_TEXT + "\n\nПринимаете правила?"):
                open(flag, "w").close()
            else:
                self.root.destroy()

    def _process_log_queue(self):
        try:
            while True:
                level, msg = self.log_queue.get_nowait()
                self.log_text.config(state=tk.NORMAL)
                tag = level.lower()
                self.log_text.insert(tk.END, msg + "\n", tag)
                self.log_text.tag_config("error", foreground="red")
                self.log_text.tag_config("warning", foreground="orange")
                self.log_text.tag_config("info", foreground="blue")
                self.log_text.see(tk.END)
                self.log_text.config(state=tk.DISABLED)
        except queue.Empty:
            pass
        self.root.after(100, self._process_log_queue)

    def _clear_logs(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)

    def _append_info(self, text):
        self.info_text.config(state=tk.NORMAL)
        self.info_text.insert(tk.END, text + "\n")
        self.info_text.see(tk.END)
        self.info_text.config(state=tk.DISABLED)

    def _refresh_clients(self):
        with self.clients_lock:
            for item in self.tree.get_children():
                self.tree.delete(item)
            for addr, info in self.clients.items():
                self.tree.insert("", tk.END, values=(addr, info.get("device_id", "?"), info.get("cpu", "?"),
                    info.get("mem", "?"), "Да" if info.get("av") else "Нет", info.get("status", "?"), info.get("time", "?")))
        self.ind_clients.config(text=f" Клиентов: {len(self.clients)} ")

    def _kick_client(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Внимание", "Выберите клиента в таблице")
            return
        item = self.tree.item(sel[0])
        ip = item["values"][0]
        messagebox.showinfo("Отключение", f"Клиент {ip} будет отключён (заглушка)")

    def _start_server(self):
        if self.running:
            return
        self.stop_event.clear()
        self.server_thread = threading.Thread(target=self._server_loop, daemon=True)
        self.server_thread.start()
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self._set_indicator(self.ind_server, "Сервер: запущен", "green")

    def _stop_server(self):
        self.stop_event.set()
        self.running = False
        self._set_indicator(self.ind_server, "Сервер: остановлен", "red")
        self._set_indicator(self.ind_tls, "TLS: неактивен", "gray")
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self._append_info("[SYSTEM] Сервер остановлен пользователем.")

    def _set_indicator(self, w, t, c):
        w.config(text=f" {t} ", bg=c)

    def _server_loop(self):
        port = int(self.port_var.get())
        host = self.host_var.get()
        ca = self.cert_vars["ca_cert"].get()
        cert = self.cert_vars["server_cert"].get()
        key = self.cert_vars["server_key"].get()
        for f in [ca, cert, key]:
            if not os.path.exists(f):
                self.logger.error(f"Файл не найден: {f}")
                self.root.after(0, self._stop_server)
                return
        try:
            tls = TLSEngine(ca, cert, key, is_server=True, logger=self.logger)
            ctx = tls.create_context()
            self._append_info(f"Сервер слушает {host}:{port}...")
            self.logger.info(f"Сервер политики запущен на {host}:{port}")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, port))
                s.listen(5)
                s.settimeout(1.0)
                self.running = True
                while not self.stop_event.is_set():
                    try:
                        conn, addr = s.accept()
                    except socket.timeout:
                        continue
                    t = threading.Thread(target=self._handle_client, args=(conn, addr, ctx), daemon=True)
                    t.start()
        except Exception as e:
            self.logger.error(f"Ошибка сервера: {e}")
            self._append_info(f"[ERROR] {e}")
            self.root.after(0, self._stop_server)

    def _handle_client(self, conn, addr, ctx):
        client_id = f"{addr[0]}:{addr[1]}"
        self.logger.info(f"Новое соединение: {client_id}")
        self._append_info(f"[CONNECT] {client_id}")
        try:
            with ctx.wrap_socket(conn, server_side=True) as ssock:
                self._set_indicator(self.ind_tls, "TLS: активен", "green")
                self.logger.info(f"mTLS успешен для {client_id}")
                data = b""
                while b"\n" not in data:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                telemetry = json.loads(data.decode().strip())
                dev_id = telemetry.get("device_id", "unknown")
                cpu = telemetry.get("cpu_percent", 0)
                mem = telemetry.get("memory_percent", 0)
                av = telemetry.get("antivirus", {}).get("detected", False)
                decision = self.policy.evaluate(telemetry)
                ssock.sendall((json.dumps(decision) + "\n").encode())
                with self.clients_lock:
                    self.clients[client_id] = {
                        "device_id": dev_id, "cpu": cpu, "mem": mem, "av": av,
                        "status": "Разрешён" if decision["allowed"] else "ОТКАЗ",
                        "time": datetime.now().strftime("%H:%M:%S"), "socket": ssock
                    }
                self.root.after(0, self._refresh_clients)
                if decision["allowed"]:
                    self.logger.info(f"Доступ разрешён {dev_id}")
                    while not self.stop_event.is_set():
                        try:
                            ssock.settimeout(2.0)
                            buf = ssock.recv(65535)
                            if not buf:
                                break
                            ssock.sendall(buf)
                        except socket.timeout:
                            pass
                else:
                    self.logger.warning(f"Доступ запрещён {dev_id}: {decision['reason']}")
                    self._append_info(f"[POLICY] Отказ для {dev_id}: {decision['reason']}")
        except Exception as e:
            self.logger.error(f"Ошибка клиента {client_id}: {e}")
        finally:
            with self.clients_lock:
                self.clients.pop(client_id, None)
            self.root.after(0, self._refresh_clients)
            self._append_info(f"[DISCONNECT] {client_id}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ServerApp(root)
    root.mainloop()
