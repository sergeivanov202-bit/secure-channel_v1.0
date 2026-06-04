"""
Общие модули для клиента и сервера СПО защищённого канала.
Версия с поддержкой GUI (threading, queue-based логирование).
"""

import os
import sys
import json
import ssl
import socket
import threading
import queue
import platform
import psutil
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, Callable

class GuiLogger:
    """Потокобезопасный логгер с выводом в GUI через queue."""
    def __init__(self, log_queue: queue.Queue):
        self.q = log_queue

    def _log(self, level: str, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] [{level}] {msg}"
        self.q.put((level, line))
        print(line)

    def debug(self, msg): self._log("DEBUG", msg)
    def info(self, msg): self._log("INFO", msg)
    def warning(self, msg): self._log("WARNING", msg)
    def error(self, msg): self._log("ERROR", msg)

class ConfigManager:
    def __init__(self, path: str = "config.json"):
        self.path = path
        self.data = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        return self._defaults()

    def _defaults(self) -> dict:
        return {
            "server_host": "127.0.0.1",
            "server_port": 8443,
            "tun_enabled": True,
            "tun_name": "tun0",
            "tun_addr": "10.200.0.2",
            "tun_netmask": "255.255.255.0",
            "tun_mtu": 1400,
            "ca_cert": "certs/ca.crt",
            "cert": "certs/client.crt",
            "key": "certs/client.key",
            "log_level": "INFO",
            "heartbeat": 30
        }

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):
        self.data[key] = value
        self.save()

    def save(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)

class TLSEngine:
    def __init__(self, ca: str, cert: str, key: str, is_server: bool = False,
                 verify_callback: Optional[Callable] = None, logger: Optional[GuiLogger] = None):
        self.ca = ca
        self.cert = cert
        self.key = key
        self.is_server = is_server
        self.logger = logger

    def create_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if self.is_server else ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(self.cert, self.key)
        ctx.load_verify_locations(self.ca)
        if self.is_server:
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = True
        ctx.set_ciphers("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256")
        if self.logger:
            self.logger.info("SSL-контекст создан (TLS 1.3, mTLS)")
        return ctx

class TelemetryCollector:
    def collect(self) -> Dict[str, Any]:
        return {
            "device_id": self._device_id(),
            "timestamp": datetime.utcnow().isoformat(),
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine()
            },
            "cpu_percent": psutil.cpu_percent(interval=0.5),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent,
            "processes": len(psutil.pids()),
            "antivirus": self._check_av(),
            "integrity": self._integrity()
        }

    def _device_id(self) -> str:
        try:
            import uuid
            return str(uuid.getnode())
        except Exception:
            return "unknown"

    def _check_av(self) -> Dict:
        av_names = ["avp", "avast", "eset", "drweb", "klnagent", "msmpeng", "ccsvchst"]
        found = []
        for proc in psutil.process_iter(['name']):
            try:
                if any(av in proc.info['name'].lower() for av in av_names):
                    found.append(proc.info['name'])
            except Exception:
                pass
        return {"detected": len(found) > 0, "processes": found}

    def _integrity(self) -> str:
        data = json.dumps(self.collect(), sort_keys=True, default=str)
        return hashlib.sha256(data.encode()).hexdigest()[:16]

class PolicyEngine:
    def __init__(self, rules: Optional[Dict] = None):
        self.rules = rules or {
            "max_cpu": 95.0,
            "antivirus_required": False,
            "denied_countries": []
        }

    def evaluate(self, telemetry: Dict) -> Dict:
        violations = []
        cpu = telemetry.get("cpu_percent", 0)
        if cpu > self.rules.get("max_cpu", 100):
            violations.append(f"CPU {cpu}% > лимит {self.rules['max_cpu']}%")
        if self.rules.get("antivirus_required"):
            if not telemetry.get("antivirus", {}).get("detected"):
                violations.append("Антивирус не обнаружен")
        allowed = len(violations) == 0
        return {
            "allowed": allowed,
            "reason": "; ".join(violations) if violations else "OK",
            "timestamp": datetime.utcnow().isoformat(),
            "rules_applied": list(self.rules.keys())
        }

class TunInterface:
    def __init__(self, name: str, addr: str, netmask: str, mtu: int = 1400, logger=None):
        self.name = name
        self.addr = addr
        self.netmask = netmask
        self.mtu = mtu
        self.logger = logger
        self._fd = None
        self._platform = platform.system()

    def is_supported(self) -> bool:
        if self._platform == "Linux":
            return os.path.exists("/dev/net/tun")
        if self._platform == "Windows":
            dll_path = os.path.join(os.path.dirname(sys.executable), "wintun.dll")
            return os.path.exists(dll_path)
        return False

    def create(self) -> bool:
        if self._platform == "Linux":
            return self._create_linux()
        elif self._platform == "Windows":
            return self._create_windows()
        else:
            if self.logger:
                self.logger.warning("TUN не поддерживается на этой платформе")
            return False

    def _create_linux(self) -> bool:
        try:
            import fcntl
            import struct
            TUNSETIFF = 0x400454ca
            IFF_TUN = 0x0001
            IFF_NO_PI = 0x1000
            self._fd = os.open("/dev/net/tun", os.O_RDWR)
            ifr = struct.pack("16sH", self.name.encode(), IFF_TUN | IFF_NO_PI)
            fcntl.ioctl(self._fd, TUNSETIFF, ifr)
            cidr = sum(bin(int(x)).count('1') for x in self.netmask.split('.'))
            os.system(f"ip addr add {self.addr}/{cidr} dev {self.name} 2>/dev/null")
            os.system(f"ip link set dev {self.name} mtu {self.mtu} 2>/dev/null")
            os.system(f"ip link set dev {self.name} up 2>/dev/null")
            os.set_blocking(self._fd, False)
            if self.logger:
                self.logger.info(f"TUN {self.name} создан ({self.addr})")
            return True
        except Exception as e:
            if self.logger:
                self.logger.error(f"Ошибка TUN Linux: {e}")
            return False

    def _create_windows(self) -> bool:
        if self.logger:
            self.logger.warning("Windows TUN требует wintun.dll")
        return False

    def read(self) -> Optional[bytes]:
        if self._fd is None:
            return None
        try:
            return os.read(self._fd, self.mtu)
        except (BlockingIOError, OSError):
            return None

    def write(self, data: bytes) -> bool:
        if self._fd is None:
            return False
        try:
            os.write(self._fd, data)
            return True
        except OSError:
            return False

    def close(self):
        if self._fd:
            os.close(self._fd)
            self._fd = None
        if self._platform == "Linux":
            os.system(f"ip link del {self.name} 2>/dev/null")
        if self.logger:
            self.logger.info(f"TUN {self.name} удалён")

class NetUtils:
    @staticmethod
    def enable_forwarding():
        os.system("sysctl -w net.ipv4.ip_forward=1 2>/dev/null")

    @staticmethod
    def add_route(dest: str, gw: str, iface: str):
        os.system(f"ip route add {dest} via {gw} dev {iface} 2>/dev/null")

    @staticmethod
    def setup_iptables(tun: str, server_ip: str, port: int):
        cmds = [
            f"iptables -t nat -A POSTROUTING -o {tun} -j MASQUERADE 2>/dev/null",
            f"iptables -A FORWARD -i {tun} -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null",
            f"iptables -A OUTPUT -p tcp -d {server_ip} --dport {port} -j ACCEPT 2>/dev/null",
        ]
        for c in cmds:
            os.system(c)

    @staticmethod
    def flush_iptables(tun: str):
        os.system(f"iptables -t nat -D POSTROUTING -o {tun} -j MASQUERADE 2>/dev/null")
