"""
scanner.py — модуль сканирования сети.

Использует:
  - python-nmap (python-nmap) для обнаружения хостов и открытых портов
  - scapy для ARP-сканирования (требует root/admin)
  - socket для получения имён хостов

Если nmap недоступен, используется только Scapy ARP + socket-fallback.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import subprocess
import sys
from typing import Any

from model import Device

logger = logging.getLogger("scanner")

# ─── Попытка импорта опциональных зависимостей ──────────────────────────────
try:
    import nmap as nmap_lib  # python-nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    logger.warning("python-nmap не установлен. Сканирование портов ограничено.")

try:
    from scapy.all import ARP, Ether, srp, conf as scapy_conf  # type: ignore
    # Отключаем лишний вывод Scapy
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("scapy не установлен. ARP-сканирование недоступно.")

try:
    from mac_vendor_lookup import MacLookup  # type: ignore
    _mac_lookup = MacLookup()
    MAC_LOOKUP_AVAILABLE = True
except ImportError:
    MAC_LOOKUP_AVAILABLE = False
    logger.warning("mac-vendor-lookup не установлен. Определение производителя недоступно.")


# Порты для быстрого сканирования (nmap -p)
QUICK_PORTS = "22,23,25,53,80,161,443,445,3389,8080,8443"


class NetworkScanner:
    """
    Сканер сети.

    Алгоритм:
    1. ARP-sweep через Scapy (если доступен и есть права) — быстрее и надёжнее в LAN.
    2. ICMP ping через nmap (если Scapy недоступен или как дополнение).
    3. Для каждого живого хоста — сканирование портов через nmap.
    4. Сбор ARP-таблиц с шлюзов (эвристика).
    """

    def __init__(
        self,
        subnet: str,
        timeout: float = 1.0,
        max_hosts: int = 254,
        snmp_community: str = "public",
    ) -> None:
        self.subnet = subnet
        self.timeout = timeout
        self.max_hosts = max_hosts
        self.snmp_community = snmp_community
        self._arp_table: dict[str, list[tuple[str, str]]] = {}
        self._found_hosts: list[Device] = []

        # Проверяем корректность подсети
        try:
            self._network = ipaddress.ip_network(subnet, strict=False)
        except ValueError as exc:
            raise ValueError(f"Некорректный формат подсети: {subnet}") from exc

    # ─────────────────────────────────────────────────────────────────────────

    def scan(self) -> list[Device]:
        """
        Запускает сканирование и возвращает список найденных устройств.
        Может поднять PermissionError при недостатке прав.
        """
        logger.info("Сканирование %s (timeout=%.1fs, max_hosts=%d)",
                    self.subnet, self.timeout, self.max_hosts)

        hosts: dict[str, Device] = {}  # ip → Device

        # ── Шаг 1: ARP-сканирование (Scapy) ──────────────────────────────
        if SCAPY_AVAILABLE:
            arp_hosts = self._arp_scan()
            for dev in arp_hosts:
                hosts[dev.ip] = dev
            logger.info("ARP-скан: найдено %d хостов", len(arp_hosts))
        else:
            logger.info("Scapy недоступен, пропускаем ARP-скан")

        # ── Шаг 2: nmap ping-скан (дополняет или заменяет ARP) ───────────
        if NMAP_AVAILABLE:
            nmap_hosts = self._nmap_ping_scan()
            for dev in nmap_hosts:
                if dev.ip not in hosts:
                    hosts[dev.ip] = dev
            logger.info("nmap ping-скан: всего хостов %d", len(hosts))
        else:
            logger.info("nmap недоступен, пропускаем ping-скан")

        # Ограничение числа хостов для безопасности
        all_hosts = list(hosts.values())[: self.max_hosts]
        if len(hosts) > self.max_hosts:
            logger.warning(
                "Обнаружено %d хостов, обрабатываем первые %d (--max-hosts)",
                len(hosts), self.max_hosts
            )

        # ── Шаг 3: Сканирование портов для каждого хоста ─────────────────
        if NMAP_AVAILABLE and all_hosts:
            self._nmap_port_scan(all_hosts)

        # ── Шаг 4: Resolve hostname ───────────────────────────────────────
        for dev in all_hosts:
            dev.hostname = self._resolve_hostname(dev.ip)

        # ── Шаг 5: MAC-vendor lookup ──────────────────────────────────────
        if MAC_LOOKUP_AVAILABLE:
            for dev in all_hosts:
                if dev.mac:
                    dev.vendor = self._lookup_vendor(dev.mac)

        self._found_hosts = all_hosts
        return all_hosts

    # ─── ARP-сканирование (Scapy) ────────────────────────────────────────────

    def _arp_scan(self) -> list[Device]:
        """
        Рассылает ARP-запросы по всей подсети.
        Требует прав root/администратора.
        Работает только в локальной сети (L2).
        """
        devices: list[Device] = []
        try:
            # Формируем ARP-пакет: Who has <subnet>? Tell me.
            arp_request = ARP(pdst=self.subnet)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request

            # srp — send/receive на L2 (Ethernet)
            answered, _ = srp(packet, timeout=self.timeout, verbose=False)

            for _, recv in answered:
                dev = Device(ip=recv.psrc, mac=recv.hwsrc.upper())
                devices.append(dev)

        except PermissionError:
            logger.error(
                "Для ARP-сканирования нужны права root/администратора. "
                "Запустите с sudo (Linux) или от Администратора (Windows)."
            )
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("Ошибка ARP-скана: %s", exc)

        return devices

    # ─── nmap ping-сканирование ──────────────────────────────────────────────

    def _nmap_ping_scan(self) -> list[Device]:
        """
        Использует nmap -sn (ping scan) для поиска живых хостов.
        Работает без прав root, но менее точен в LAN.
        """
        nm = nmap_lib.PortScanner()
        devices: list[Device] = []
        try:
            # -sn: только ping (без сканирования портов)
            # --host-timeout: защита от зависания
            nm.scan(
                hosts=self.subnet,
                arguments=f"-sn --host-timeout {int(self.timeout * 1000)}ms",
            )
        except nmap_lib.PortScannerError as exc:
            logger.error("nmap ошибка (nmap установлен?): %s", exc)
            return devices

        for ip in nm.all_hosts():
            host_info = nm[ip]
            if host_info.state() == "up":
                mac = None
                # nmap может вернуть MAC в addresses
                if "mac" in host_info.get("addresses", {}):
                    mac = host_info["addresses"]["mac"].upper()
                dev = Device(ip=ip, mac=mac)
                # TTL из nmap (если есть в данных)
                devices.append(dev)

        return devices

    # ─── nmap сканирование портов ────────────────────────────────────────────

    def _nmap_port_scan(self, hosts: list[Device]) -> None:
        """
        Сканирует открытые порты для каждого хоста (быстрый режим).
        Обновляет поле open_ports у каждого Device.
        """
        nm = nmap_lib.PortScanner()
        ip_list = " ".join(dev.ip for dev in hosts)

        try:
            # -T4: агрессивный таймаут; --open: только открытые порты
            nm.scan(
                hosts=ip_list,
                ports=QUICK_PORTS,
                arguments=f"-T4 --open --host-timeout {int(self.timeout * 2000)}ms",
            )
        except nmap_lib.PortScannerError as exc:
            logger.warning("Ошибка сканирования портов: %s", exc)
            return

        # Ищем устройство по IP и обновляем порты
        ip_to_dev = {dev.ip: dev for dev in hosts}
        for ip in nm.all_hosts():
            if ip not in ip_to_dev:
                continue
            dev = ip_to_dev[ip]
            for proto in nm[ip].all_protocols():
                for port, port_info in nm[ip][proto].items():
                    if port_info["state"] == "open":
                        dev.open_ports.append(port)
            logger.debug("%s: открытые порты %s", ip, dev.open_ports)

            # TTL из nmap (в некоторых версиях доступен)
            try:
                dev.ttl = nm[ip]["status"].get("reason_ttl")
            except (KeyError, AttributeError):
                pass

    # ─── Вспомогательные методы ──────────────────────────────────────────────

    @staticmethod
    def _resolve_hostname(ip: str) -> str | None:
        """Reverse-DNS resolve. Не блокирует надолго — timeout ~1 сек."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return None

    @staticmethod
    def _lookup_vendor(mac: str) -> str | None:
        """Определение производителя по первым 3 байтам MAC (OUI)."""
        if not MAC_LOOKUP_AVAILABLE:
            return None
        try:
            return _mac_lookup.lookup(mac)
        except Exception:  # noqa: BLE001
            return None

    def get_arp_table(self) -> dict[str, list[tuple[str, str]]]:
        """
        Возвращает ARP-таблицу, построенную во время сканирования.
        Ключ — IP шлюза (первое обнаруженное устройство типа router/switch),
        значение — список (ip, mac) соседей.

        В текущей реализации — простая эвристика: если есть роутер,
        все остальные хосты считаются его соседями в LAN.
        """
        if not self._found_hosts:
            return {}

        # Ищем вероятный шлюз (.1 в подсети)
        network = self._network
        gateway_ip = str(network.network_address + 1)

        gateway_dev = None
        for dev in self._found_hosts:
            if dev.ip == gateway_ip:
                gateway_dev = dev
                break

        if not gateway_dev and self._found_hosts:
            gateway_dev = self._found_hosts[0]

        if not gateway_dev:
            return {}

        # Все остальные хосты — соседи шлюза
        neighbors = [
            (dev.ip, dev.mac or "")
            for dev in self._found_hosts
            if dev.ip != gateway_dev.ip
        ]
        return {gateway_dev.ip: neighbors}


# ─── Утилита: ping через subprocess (Windows/Linux portable) ─────────────────

def ping_host(ip: str, timeout: float = 1.0) -> bool:
    """
    Проверяет доступность хоста через ICMP ping.
    Не требует прав root — использует системную утилиту ping.
    Платформозависимо: аргументы отличаются для Windows и Linux/Mac.
    """
    if sys.platform == "win32":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
