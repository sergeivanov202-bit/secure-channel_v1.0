#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Клиент СПО защищённого канала — GUI версия."""

import os
import sys
import json
import time
import threading
import queue
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import GuiLogger, ConfigManager, TLSEngine, TelemetryCollector, TunInterface, NetUtils

RULES_TEXT = """╔══════════════════════════════════════════════════════════════════╗
║                    ПРАВИЛА ПОЛЬЗОВАНИЯ ПРОГРАММОЙ                 ║
╠══════════════════════════════════════════════════════════════════╣
1. Программа предназначена для создания защищённого канала связи
   с использованием протокола TLS 1.3 и архитектуры Zero Trust.
2. Запускайте приложение только от имени администратора/root.
3. Перед подключением убедитесь, что файлы сертификатов существуют.
4. При передаче телеметрии собираются только технические параметры.
5. Запрещается использование программы для обхода законодательства РФ.
6. Для Windows TUN требуется файл wintun.dll рядом с программой.
╚══════════════════════════════════════════════════════════════════╝"""

HELP_TEXT = """ИНСТРУКЦИЯ ПО ПРИМЕНЕНИЮ (Клиент)
1. ПОДГОТОВКА: укажите пути к CA, client.crt, client.key.
2. НАСТРОЙКА: адрес сервера, порт, TUN-адрес.
3. РЕЖИМЫ: TUN-режим (требует root) или демо-режим.
4. ПОДКЛЮЧЕНИЕ: нажмите «Подключиться».
5. СБОРКА .EXE: pyinstaller --windowed --onefile client_gui.py"""

class ClientApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("СПО Защищённый канал — Клиент (mTLS + Zero Trust)")
        self.root.geometry("900x700")
        self.log_queue = queue.Queue()
        self.logger = GuiLogger(self.log_queue)
        self.cfg = ConfigManager("client_config.json")
        self.connected = False
        self.stop_event = threading.Event()
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
        ind_frame = ttk.LabelFrame(tab_main, text="Статус соединения")
        ind_frame.pack(fill=tk.X, padx=10, pady=10)
        self.ind_tls = tk.Label(ind_frame, text=" TLS: неактивен ", bg="gray", fg="white", font=("Arial", 11, "bold"))
        self.ind_tls.pack(side=tk.LEFT, padx=5, pady=5)
        self.ind_tun = tk.Label(ind_frame, text=" TUN: неактивен ", bg="gray", fg="white", font=("Arial", 11, "bold"))
        self.ind_tun.pack(side=tk.LEFT, padx=5, pady=5)
        self.ind_policy = tk.Label(ind_frame, text=" Политика: ожидание ", bg="gray", fg="white", font=("Arial", 11, "bold"))
        self.ind_policy.pack(side=tk.LEFT, padx=5, pady=5)
        self.ind_channel = tk.Label(ind_frame, text=" Канал: отключён ", bg="red", fg="white", font=("Arial", 11, "bold"))
        self.ind_channel.pack(side=tk.LEFT, padx=5, pady=5)

        btn_frame = ttk.Frame(tab_main)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        self.btn_connect = ttk.Button(btn_frame, text="Подключиться", command=self._connect, width=20)
        self.btn_connect.pack(side=tk.LEFT, padx=5)
        self.btn_disconnect = ttk.Button(btn_frame, text="Отключиться", command=self._disconnect, width=20, state=tk.DISABLED)
        self.btn_disconnect.pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Показать правила", command=self._show_rules).pack(side=tk.RIGHT, padx=5)

        info_frame = ttk.LabelFrame(tab_main, text="Информация о сессии")
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.info_text = scrolledtext.ScrolledText(info_frame, wrap=tk.WORD, state=tk.DISABLED, height=10)
        self.info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Конфигурация
        tab_cfg = ttk.Frame(self.notebook)
        self.notebook.add(tab_cfg, text=" Конфигурация ")
        cfg_frame = ttk.Frame(tab_cfg)
        cfg_frame.pack(fill=tk.X, padx=10, pady=10)
        fields = [
            ("Адрес сервера:", "server_host", self.cfg.get("server_host")),
            ("Порт:", "server_port", str(self.cfg.get("server_port"))),
            ("TUN имя:", "tun_name", self.cfg.get("tun_name")),
            ("TUN IP:", "tun_addr", self.cfg.get("tun_addr")),
            ("TUN маска:", "tun_netmask", self.cfg.get("tun_netmask")),
            ("MTU:", "tun_mtu", str(self.cfg.get("tun_mtu"))),
        ]
        self.cfg_vars = {}
        for i, (label, key, val) in enumerate(fields):
            ttk.Label(cfg_frame, text=label).grid(row=i, column=0, sticky=tk.W, padx=5, pady=3)
            var = tk.StringVar(value=val)
            self.cfg_vars[key] = var
            ttk.Entry(cfg_frame, textvariable=var, width=30).grid(row=i, column=1, sticky=tk.W, padx=5, pady=3)

        cert_frame = ttk.LabelFrame(tab_cfg, text="Сертификаты X.509")
        cert_frame.pack(fill=tk.X, padx=10, pady=10)
        self.cert_paths = {}
        for i, (label, key) in enumerate([("CA сертификат", "ca_cert"), ("Клиент cert", "cert"), ("Клиент key", "key")]):
            ttk.Label(cert_frame, text=label).grid(row=i, column=0, sticky=tk.W, padx=5, pady=3)
            var = tk.StringVar(value=self.cfg.get(key, ""))
            self.cert_paths[key] = var
            ttk.Entry(cert_frame, textvariable=var, width=40).grid(row=i, column=1, sticky=tk.W, padx=5, pady=3)
            ttk.Button(cert_frame, text="Обзор...", command=lambda v=var: self._browse_file(v)).grid(row=i, column=2, padx=5)

        self.tun_var = tk.BooleanVar(value=self.cfg.get("tun_enabled", True))
        ttk.Checkbutton(tab_cfg, text="Использовать TUN-интерфейс (требует root/администратора)", variable=self.tun_var).pack(anchor=tk.W, padx=10, pady=5)
        ttk.Button(tab_cfg, text="Сохранить настройки", command=self._save_config).pack(anchor=tk.W, padx=10, pady=10)
        ttk.Button(tab_cfg, text="Создать тестовые сертификаты", command=self._gen_test_certs).pack(anchor=tk.W, padx=10, pady=5)

        # Логи
        tab_logs = ttk.Frame(self.notebook)
        self.notebook.add(tab_logs, text="  Логи  ")
        self.log_text = scrolledtext.ScrolledText(tab_logs, wrap=tk.WORD, state=tk.DISABLED, height=20)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        ttk.Button(tab_logs, text="Очистить", command=self._clear_logs).pack(anchor=tk.E, padx=5, pady=5)

        # Справка
        tab_help = ttk.Frame(self.notebook)
        self.notebook.add(tab_help, text="  Справка  ")
        help_text = scrolledtext.ScrolledText(tab_help, wrap=tk.WORD, state=tk.DISABLED)
        help_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        help_text.config(state=tk.NORMAL)
        help_text.insert(tk.END, RULES_TEXT + "\n\n" + HELP_TEXT)
        help_text.config(state=tk.DISABLED)

    def _browse_file(self, var: tk.StringVar):
        path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem *.crt *.key"), ("All files", "*.*")])
        if path:
            var.set(path)

    def _save_config(self):
        for key, var in self.cfg_vars.items():
            val = var.get()
            if key in ["server_port", "tun_mtu"]:
                val = int(val)
            self.cfg.set(key, val)
        for key, var in self.cert_paths.items():
            self.cfg.set(key, var.get())
        self.cfg.set("tun_enabled", self.tun_var.get())
        messagebox.showinfo("Сохранено", "Настройки записаны в client_config.json")

    def _gen_test_certs(self):
        import subprocess
        os.makedirs("certs", exist_ok=True)
        cmds = [
            'openssl req -x509 -newkey rsa:2048 -keyout certs/ca.key -out certs/ca.crt -days 365 -nodes -subj "/CN=Test-CA"',
            'openssl req -newkey rsa:2048 -keyout certs/client.key -out certs/client.csr -nodes -subj "/CN=test-client"',
            'openssl x509 -req -in certs/client.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/client.crt -days 365'
        ]
        for c in cmds:
            subprocess.run(c, shell=True, capture_output=True)
        self.cert_paths["ca_cert"].set(os.path.abspath("certs/ca.crt"))
        self.cert_paths["cert"].set(os.path.abspath("certs/client.crt"))
        self.cert_paths["key"].set(os.path.abspath("certs/client.key"))
        messagebox.showinfo("Готово", "Тестовые сертификаты созданы в папке certs/")

    def _show_rules(self):
        win = tk.Toplevel(self.root)
        win.title("Правила пользования")
        win.geometry("600x500")
        txt = scrolledtext.ScrolledText(win, wrap=tk.WORD)
        txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        txt.insert(tk.END, RULES_TEXT)
        txt.config(state=tk.DISABLED)
        ttk.Button(win, text="Закрыть", command=win.destroy).pack(pady=5)

    def _show_help(self):
        win = tk.Toplevel(self.root)
        win.title("Инструкция")
        win.geometry("700x600")
        txt = scrolledtext.ScrolledText(win, wrap=tk.WORD)
        txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        txt.insert(tk.END, HELP_TEXT)
        txt.config(state=tk.DISABLED)
        ttk.Button(win, text="Закрыть", command=win.destroy).pack(pady=5)

    def _show_about(self):
        messagebox.showinfo("О программе", "СПО Защищённый канал\nВерсия: 1.0 (GUI)\nТехнологии: Python 3, TLS 1.3, mTLS, Zero Trust, TUN\nАвтор: Котомин С.М.\nВОРЭ (г. Череповец)")

    def _show_rules_on_first_run(self):
        flag_file = ".rules_accepted"
        if not os.path.exists(flag_file):
            if messagebox.askyesno("Правила пользования", RULES_TEXT + "\n\nПринимаете правила и готовы продолжить?"):
                open(flag_file, "w").close()
            else:
                self.root.destroy()

    def _set_indicator(self, widget, text, color):
        widget.config(text=f" {text} ", bg=color)

    def _log(self, level, msg):
        self.log_queue.put((level, msg))

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
                self.log_text.tag_config("debug", foreground="gray")
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

    def _connect(self):
        if self.connected:
            return
        self.stop_event.clear()
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.worker_thread.start()
        self.btn_connect.config(state=tk.DISABLED)
        self.btn_disconnect.config(state=tk.NORMAL)

    def _disconnect(self):
        self.stop_event.set()
        self.connected = False
        self._set_indicator(self.ind_channel, "Канал: отключён", "red")
        self._set_indicator(self.ind_tls, "TLS: неактивен", "gray")
        self._set_indicator(self.ind_tun, "TUN: неактивен", "gray")
        self._set_indicator(self.ind_policy, "Политика: ожидание", "gray")
        self.btn_connect.config(state=tk.NORMAL)
        self.btn_disconnect.config(state=tk.DISABLED)
        self._append_info("[SYSTEM] Отключение инициировано пользователем.")

    def _worker(self):
        try:
            self._append_info("[1/7] Инициализация...")
            host = self.cfg_vars["server_host"].get()
            port = int(self.cfg_vars["server_port"].get())
            ca = self.cert_paths["ca_cert"].get()
            cert = self.cert_paths["cert"].get()
            key = self.cert_paths["key"].get()
            use_tun = self.tun_var.get()
            for f in [ca, cert, key]:
                if not os.path.exists(f):
                    self.logger.error(f"Файл не найден: {f}")
                    self._append_info(f"[ERROR] Файл не найден: {f}")
                    self._disconnect()
                    return
            tun = None
            if use_tun:
                self._append_info("[2/7] Создание TUN-интерфейса...")
                tun = TunInterface(self.cfg_vars["tun_name"].get(), self.cfg_vars["tun_addr"].get(),
                    self.cfg_vars["tun_netmask"].get(), int(self.cfg_vars["tun_mtu"].get()), logger=self.logger)
                if not tun.create():
                    self._append_info("[WARNING] TUN не создан. Демо-режим.")
                    self._set_indicator(self.ind_tun, "TUN: недоступен", "orange")
                else:
                    self._set_indicator(self.ind_tun, "TUN: активен", "green")
                    NetUtils.enable_forwarding()
            else:
                self._append_info("[2/7] TUN отключён.")
                self._set_indicator(self.ind_tun, "TUN: выкл", "gray")
            self._append_info("[3/7] Формирование TLS-контекста...")
            tls = TLSEngine(ca, cert, key, is_server=False, logger=self.logger)
            ctx = tls.create_context()
            self._append_info(f"[4/7] Подключение к {host}:{port}...")
            sock = socket.create_connection((host, port), timeout=10)
            self.logger.info("TCP-соединение установлено")
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                self.logger.info("TLS 1.3 handshake завершён (mTLS)")
                self._set_indicator(self.ind_tls, "TLS: активен", "green")
                self._append_info(f"[5/7] TLS установлен. Шифрнабор: {ssock.cipher()[0]}")
                self._append_info("[6/7] Сбор и отправка телеметрии...")
                tel = TelemetryCollector()
                data = tel.collect()
                ssock.sendall((json.dumps(data) + "\n").encode())
                self.logger.info("Телеметрия отправлена")
                resp = b""
                while b"\n" not in resp:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                decision = json.loads(resp.decode().strip())
                if decision.get("allowed"):
                    self._set_indicator(self.ind_policy, "Политика: разрешено", "green")
                    self._append_info(f"[6/7] Zero Trust: ДОСТУП РАЗРЕШЁН ({decision.get('reason', 'OK')})")
                    self.connected = True
                    self._set_indicator(self.ind_channel, "Канал: активен", "green")
                    self._append_info("[7/7] Канал активирован. Обмен данными...")
                    self.logger.info("Канал активен")
                    while not self.stop_event.is_set():
                        if tun:
                            packet = tun.read()
                            if packet:
                                ssock.sendall(packet)
                        try:
                            ssock.settimeout(1.0)
                            data = ssock.recv(self.cfg.get("tun_mtu", 1400))
                            if data and tun:
                                tun.write(data)
                        except socket.timeout:
                            pass
                        time.sleep(0.01)
                else:
                    reason = decision.get("reason", "неизвестно")
                    self._set_indicator(self.ind_policy, "Политика: ОТКАЗ", "red")
                    self._append_info(f"[6/7] Zero Trust: ДОСТУП ЗАПРЕЩЁН — {reason}")
                    self.logger.warning(f"Доступ запрещён: {reason}")
        except Exception as e:
            self.logger.error(f"Ошибка: {e}")
            self._append_info(f"[ERROR] {e}")
        finally:
            if tun:
                tun.close()
            self.connected = False
            self.root.after(0, lambda: self._set_indicator(self.ind_channel, "Канал: отключён", "red"))
            self.root.after(0, lambda: self.btn_connect.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.btn_disconnect.config(state=tk.DISABLED))

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientApp(root)
    root.mainloop()
