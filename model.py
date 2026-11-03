"""
model.py — модель данных топологии сети.

ТИПЫ УСТРОЙСТВ:
  Сетевое оборудование : router, firewall, switch, bridge, access_point
  Серверы              : windows_server, linux_server, server, nas
  Конечные точки       : windows_endpoint, linux_endpoint, printer, voip_phone,
                         ip_camera, iot, endpoint
  Мобильные            : mobile_device
  Прочее               : segment (виртуальный L2-сегмент), unknown

ПОСТРОЕНИЕ ТОПОЛОГИИ (build_from_results):
  1. Хосты всех подсетей добавляются в граф, дубликаты по IP объединяются.
  2. Объединение мультиинтерфейсных устройств: по IP-алиасам (SNMP ipAdEntAddr)
     и по MAC (с защитой от proxy-ARP).
  3. Цепочка маршрутизаторов от сканера до подсети (traceroute).
  4. Явные связи (LLDP / CDP / FDB коммутаторов / ARP-таблицы маршрутизаторов).
  5. Вывод недостающих связей: шлюз подсети → коммутатор → конечные устройства.
  6. Иерархическая раскладка без наложений (layout.py).

ФОРМАТ ФАЙЛА: JSON, версия 2 (см. NetworkTopology.to_dict). Файлы версии 1
загружаются без изменений.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import tempfile
import uuid
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from typing import Any

import networkx as nx

logger = logging.getLogger("model")

APP_NAME = "Net Topology"
APP_VERSION = "2.0.0"
FILE_FORMAT = "net-topology"
FILE_VERSION = 2

# ─── Типы устройств ──────────────────────────────────────────────────────────

DEVICE_TYPES = [
    "router",
    "firewall",
    "switch",
    "bridge",
    "access_point",
    "windows_server",
    "linux_server",
    "server",
    "nas",
    "windows_endpoint",
    "linux_endpoint",
    "printer",
    "voip_phone",
    "ip_camera",
    "iot",
    "mobile_device",
    "endpoint",
    "segment",
    "unknown",
]

DEVICE_TYPE_LABELS: dict[str, str] = {
    "router":           "Маршрутизатор",
    "firewall":         "Межсетевой экран",
    "switch":           "Коммутатор",
    "bridge":           "Бридж",
    "access_point":     "Точка доступа Wi-Fi",
    "windows_server":   "Windows Server",
    "linux_server":     "Linux Server",
    "server":           "Сервер",
    "nas":              "NAS / СХД",
    "windows_endpoint": "Windows ПК",
    "linux_endpoint":   "Linux/macOS ПК",
    "printer":          "Принтер/МФУ",
    "voip_phone":       "VoIP-телефон",
    "ip_camera":        "IP-камера",
    "iot":              "IoT-устройство",
    "mobile_device":    "Мобильное устройство",
    "endpoint":         "Конечная точка",
    "segment":          "Сегмент сети",
    "unknown":          "Неизвестно",
}

DEVICE_TYPE_GROUPS: dict[str, list[str]] = {
    "Сетевое оборудование": ["router", "firewall", "switch", "bridge",
                             "access_point"],
    "Серверы":              ["windows_server", "linux_server", "server", "nas"],
    "Конечные точки":       ["windows_endpoint", "linux_endpoint", "printer",
                             "voip_phone", "ip_camera", "iot", "endpoint"],
    "Мобильные":            ["mobile_device"],
    "Прочее":               ["segment", "unknown"],
}

TYPE_COLORS: dict[str, str] = {
    "router":           "#e74c3c",
    "firewall":         "#e67e22",
    "switch":           "#2980b9",
    "bridge":           "#8e44ad",
    "access_point":     "#3f51b5",
    "windows_server":   "#16a085",
    "linux_server":     "#27ae60",
    "server":           "#1abc9c",
    "nas":              "#00897b",
    "windows_endpoint": "#34495e",
    "linux_endpoint":   "#7f8c8d",
    "printer":          "#f39c12",
    "voip_phone":       "#00bcd4",
    "ip_camera":        "#c0392b",
    "iot":              "#9c27b0",
    "mobile_device":    "#78909c",
    "endpoint":         "#95a5a6",
    "segment":          "#5d6d7e",
    "unknown":          "#bdc3c7",
}

# Сохранено для обратной совместимости (старый GUI рисовал фигуры)
TYPE_SHAPES: dict[str, str] = {
    "router": "diamond", "firewall": "triangle", "switch": "square",
    "bridge": "hexagon", "access_point": "hexagon",
    "windows_server": "circle", "linux_server": "circle", "server": "circle",
    "nas": "square", "windows_endpoint": "circle", "linux_endpoint": "circle",
    "printer": "square", "voip_phone": "hexagon", "ip_camera": "triangle",
    "iot": "hexagon", "mobile_device": "circle", "endpoint": "circle",
    "segment": "hexagon", "unknown": "circle",
}

# Иерархический «вес» типа: чем выше, тем ближе к корню дерева
TYPE_RANK: dict[str, int] = {
    "firewall": 9, "router": 9, "switch": 7, "segment": 6, "bridge": 6,
    "access_point": 5, "windows_server": 4, "linux_server": 4, "server": 3,
    "nas": 3, "windows_endpoint": 2, "linux_endpoint": 2, "printer": 2,
    "voip_phone": 2, "ip_camera": 2, "iot": 1, "mobile_device": 1,
    "endpoint": 1, "unknown": 0,
}

ROUTING_TYPES = {"router", "firewall"}
L2_TYPES = {"switch", "bridge"}

# ─── Типы связей ─────────────────────────────────────────────────────────────
# Приоритет: при повторном добавлении связи более достоверный тип заменяет менее
LINK_PRIORITY: dict[str, int] = {
    "manual": 100, "lldp": 90, "cdp": 90, "fdb": 80, "snmp-arp": 60,
    "ARP": 50, "traceroute": 50, "inter-subnet": 40, "inferred": 20,
    "heuristic": 10, "": 0,
}

LINK_LABELS: dict[str, str] = {
    "manual":       "Ручная",
    "lldp":         "LLDP",
    "cdp":          "CDP",
    "fdb":          "Таблица MAC коммутатора",
    "snmp-arp":     "ARP-таблица (SNMP)",
    "ARP":          "ARP",
    "traceroute":   "Маршрут (traceroute)",
    "inter-subnet": "Межсетевая",
    "inferred":     "Предполагаемая",
    "heuristic":    "Эвристика",
    "":             "Связь",
}

# Связи, подтверждающие физическое (L2) подключение
CONFIRMED_LINKS = {"manual", "lldp", "cdp", "fdb"}

# Атрибуты связи, описывающие её маршрут на схеме
ROUTE_KEYS = ("points", "route_src", "route_at")


# ─── Утилиты ─────────────────────────────────────────────────────────────────

def normalize_mac(mac: str) -> str:
    """
    Приводит MAC к формату AA:BB:CC:DD:EE:FF.
    Поддерживает: aa:bb:cc:dd:ee:ff / AA-BB-CC-DD-EE-FF /
                  aabb.ccdd.eeff / aabbccddeeff
    Возвращает '' если формат не распознан.
    """
    if not mac:
        return ""
    clean = re.sub(r"[:\-\.\s]", "", mac).upper()
    if len(clean) != 12 or not re.fullmatch(r"[0-9A-F]{12}", clean):
        return ""
    return ":".join(clean[i:i + 2] for i in range(0, 12, 2))


def is_laa_mac(mac: str | None) -> bool:
    """Locally Administered (рандомизированный) MAC — бит 0x02 первого октета."""
    norm = normalize_mac(mac or "")
    return bool(norm) and bool(int(norm[:2], 16) & 0x02)


def ip_sort_key(ip: str) -> tuple[int, int]:
    """Ключ сортировки IP: числовой, некорректные адреса — в конец."""
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, 0)


def ip_in_subnet(ip: str, subnet: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet,
                                                                strict=False)
    except ValueError:
        return False


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_id() -> str:
    return uuid.uuid4().hex[:8]


# ─── Interface ───────────────────────────────────────────────────────────────

@dataclass
class Interface:
    """Один сетевой интерфейс: IP + подсеть CIDR + имя порта."""
    ip: str
    subnet: str = ""
    iface_name: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"ip": self.ip, "subnet": self.subnet,
                "iface_name": self.iface_name}

    @classmethod
    def from_dict(cls, d: dict) -> "Interface":
        return cls(ip=d.get("ip", ""),
                   subnet=d.get("subnet", "") or "",
                   iface_name=d.get("iface_name", "") or "")


# ─── Device ──────────────────────────────────────────────────────────────────

@dataclass
class Device:
    """Сетевое устройство."""

    ip: str
    mac: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    device_type: str = "unknown"
    open_ports: list[int] = field(default_factory=list)
    ttl: int | None = None
    snmp_info: dict[str, str] = field(default_factory=dict)
    node_id: str = field(default_factory=_new_id)
    position: tuple[float, float] | None = None
    notes: str = ""
    subnet: str = ""
    interfaces: list[Interface] = field(default_factory=list)
    is_multihomed: bool = False
    # ── Расширенные сведения (v2) ──
    os_name: str = ""             # «Windows 10/11», «Ubuntu Linux», «Cisco IOS XE»
    os_family: str = ""           # windows / linux / macos / ios / android /
                                  # bsd / network / embedded
    model: str = ""               # модель оборудования (SNMP/HTTP)
    services: dict[int, str] = field(default_factory=dict)  # порт → баннер
    netbios_name: str = ""
    workgroup: str = ""
    hops: int | None = None       # расстояние от сканера в L3-хопах
    is_gateway: bool = False      # шлюз подсети
    is_scanner: bool = False      # компьютер, с которого велось сканирование
    is_virtual: bool = False      # виртуальный узел (сегмент сети)
    confidence: int = 0           # уверенность классификации, %
    evidence: list[str] = field(default_factory=list)
    location: str = ""            # SNMP sysLocation
    last_seen: str = ""

    def __post_init__(self) -> None:
        if self.ip and not any(i.ip == self.ip for i in self.interfaces):
            self.interfaces.insert(0, Interface(ip=self.ip, subnet=self.subnet))

    # ── Интерфейсы ──

    def add_interface(self, ip: str, subnet: str = "",
                      iface_name: str = "") -> None:
        """Добавить интерфейс без дублирования (дополняет пустые поля)."""
        for i in self.interfaces:
            if i.ip == ip:
                if subnet and not i.subnet:
                    i.subnet = subnet
                if iface_name and not i.iface_name:
                    i.iface_name = iface_name
                return
        self.interfaces.append(Interface(ip=ip, subnet=subnet,
                                         iface_name=iface_name))

    def all_ips(self) -> list[str]:
        return [i.ip for i in self.interfaces]

    def subnets(self) -> set[str]:
        result = {i.subnet for i in self.interfaces if i.subnet}
        if self.subnet:
            result.add(self.subnet)
        return result

    def interfaces_label(self) -> str:
        lines = []
        for i in self.interfaces:
            n = f" ({i.iface_name})" if i.iface_name else ""
            s = f" [{i.subnet}]" if i.subnet else ""
            lines.append(f"{i.ip}{n}{s}")
        return "\n".join(lines)

    # ── Отображение ──

    @property
    def type_label(self) -> str:
        return DEVICE_TYPE_LABELS.get(self.device_type, self.device_type)

    def display_name(self) -> str:
        """Лучшее доступное имя: DNS → NetBIOS → SNMP sysName → IP."""
        if self.is_virtual:
            return self.hostname or self.subnet or self.ip
        sys_name = self.snmp_info.get("sysName", "") if self.snmp_info else ""
        return self.hostname or self.netbios_name or sys_name or self.ip

    def label(self) -> str:
        name = self.hostname or self.ip
        if self.is_multihomed:
            return f"★ {name}\n[{self.type_label}]\n{self.interfaces_label()}"
        return f"{name}\n[{self.type_label}]"

    def summary_line(self) -> str:
        """Короткая строка «производитель · ОС» для подписи узла."""
        parts = []
        if self.vendor:
            parts.append(self.vendor)
        if self.os_name:
            parts.append(self.os_name)
        elif self.model:
            parts.append(self.model)
        if not parts:
            parts.append(self.type_label)
        return " · ".join(parts)

    # ── Сериализация ──

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["interfaces"] = [i.to_dict() for i in self.interfaces]
        d["services"] = {str(k): v for k, v in self.services.items()}
        d["position"] = list(self.position) if self.position else None
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Device":
        data = dict(data)
        known = {f.name for f in fields(cls)}
        raw_ifaces = data.pop("interfaces", []) or []
        clean = {k: v for k, v in data.items() if k in known}

        pos = clean.get("position")
        if pos is not None:
            try:
                clean["position"] = (float(pos[0]), float(pos[1]))
            except (TypeError, ValueError, IndexError):
                clean["position"] = None
        if "services" in clean and isinstance(clean["services"], dict):
            services: dict[int, str] = {}
            for k, v in clean["services"].items():
                try:
                    services[int(k)] = str(v)
                except (TypeError, ValueError):
                    continue
            clean["services"] = services
        if "open_ports" in clean:
            ports = []
            for p in clean["open_ports"] or []:
                try:
                    ports.append(int(p))
                except (TypeError, ValueError):
                    continue
            clean["open_ports"] = ports
        clean.setdefault("ip", "")

        obj = cls(**clean)
        obj.interfaces = []
        for i in raw_ifaces:
            iface = Interface.from_dict(i) if isinstance(i, dict) else i
            if not any(x.ip == iface.ip for x in obj.interfaces):
                obj.interfaces.append(iface)
        if obj.ip and not any(x.ip == obj.ip for x in obj.interfaces):
            obj.interfaces.insert(0, Interface(ip=obj.ip, subnet=obj.subnet))
        return obj


# ─── Результат сканирования подсети ──────────────────────────────────────────

@dataclass
class ScanResult:
    """Всё, что сканер узнал об одной подсети."""
    subnet: str
    devices: list[Device] = field(default_factory=list)
    # (ip_a, ip_b, тип связи, атрибуты: local_port / remote_port)
    links: list[tuple[str, str, str, dict]] = field(default_factory=list)
    gateway_ip: str | None = None      # шлюз этой подсети
    path: list[str | None] = field(default_factory=list)  # хопы до подсети
    is_local: bool = False             # сканер находится в этой подсети
    scanner_ip: str | None = None
    warnings: list[str] = field(default_factory=list)
    duration: float = 0.0


# ─── NetworkTopology ─────────────────────────────────────────────────────────

class NetworkTopology:
    """Хранилище топологии: граф NetworkX + словарь устройств."""

    def __init__(self) -> None:
        self.graph: nx.Graph = nx.Graph()
        self.devices: dict[str, Device] = {}
        self._ip_to_id: dict[str, str] = {}
        self.meta: dict[str, Any] = {}
        self.layout_mode: str = "tree"

    # ── CRUD ─────────────────────────────────────────────────────────────────

    def add_device(self, device: Device) -> str:
        nid = device.node_id
        self.devices[nid] = device
        self._ip_to_id[device.ip] = nid
        for iface in device.interfaces:
            self._ip_to_id.setdefault(iface.ip, nid)
        self.graph.add_node(nid)
        return nid

    def remove_device(self, node_id: str) -> None:
        if node_id not in self.devices:
            return
        self.devices.pop(node_id)
        for ip in [ip for ip, nid in self._ip_to_id.items() if nid == node_id]:
            del self._ip_to_id[ip]
        if self.graph.has_node(node_id):
            self.graph.remove_node(node_id)

    def reindex(self) -> None:
        """Перестроить индекс IP → устройство (после ручного редактирования)."""
        self._ip_to_id.clear()
        for nid, dev in self.devices.items():
            self._ip_to_id[dev.ip] = nid
        for nid, dev in self.devices.items():
            for iface in dev.interfaces:
                self._ip_to_id.setdefault(iface.ip, nid)

    def get_by_ip(self, ip: str) -> Device | None:
        nid = self._ip_to_id.get(ip)
        return self.devices.get(nid) if nid else None

    def get_by_mac(self, mac: str) -> Device | None:
        norm = normalize_mac(mac)
        if not norm:
            return None
        for dev in self.devices.values():
            if dev.mac and normalize_mac(dev.mac) == norm:
                return dev
        return None

    def add_link(self, src: str, dst: str, label: str = "",
                 **attrs: Any) -> None:
        """Добавить связь. Существующая связь обновляется, если новый тип
        достовернее (например, inferred → lldp)."""
        if src == dst or not (self.graph.has_node(src)
                              and self.graph.has_node(dst)):
            return
        if self.graph.has_edge(src, dst):
            data = self.graph.edges[src, dst]
            old = data.get("label", "")
            if LINK_PRIORITY.get(label, 0) > LINK_PRIORITY.get(old, 0):
                data["label"] = label
            for k, v in attrs.items():
                if v and not data.get(k):
                    data[k] = v
            return
        self.graph.add_edge(src, dst, label=label,
                            **{k: v for k, v in attrs.items() if v})

    def remove_link(self, src: str, dst: str) -> None:
        if self.graph.has_edge(src, dst):
            self.graph.remove_edge(src, dst)

    @property
    def links(self) -> list[tuple[str, str, dict]]:
        return list(self.graph.edges(data=True))

    def subnet_members(self) -> dict[str, list[str]]:
        """Подсеть → список node_id (мультиинтерфейсные — в нескольких)."""
        result: dict[str, list[str]] = {}
        for nid, dev in self.devices.items():
            for sn in dev.subnets():
                result.setdefault(sn, []).append(nid)
        return dict(sorted(result.items(), key=lambda kv: _subnet_key(kv[0])))

    # ── Построение топологии ─────────────────────────────────────────────────

    def build_from_hosts(
        self,
        hosts: list[Device],
        arp_table: dict[str, list[tuple[str, str]]] | None = None,
        subnet: str = "",
    ) -> None:
        """Одна подсеть (обратная совместимость)."""
        self.build_from_multi_subnet([(subnet, hosts, arp_table)])

    def build_from_multi_subnet(
        self,
        subnet_results: list[
            tuple[str, list[Device], dict[str, list[tuple[str, str]]] | None]
        ],
    ) -> None:
        """Несколько подсетей в старом формате (subnet, hosts, arp_table)."""
        results = []
        for subnet, hosts, arp_table in subnet_results:
            links = []
            for gw_ip, entries in (arp_table or {}).items():
                for ip, _mac in entries:
                    links.append((gw_ip, ip, "ARP", {}))
            results.append(ScanResult(subnet=subnet, devices=list(hosts),
                                      links=links))
        self.build_from_results(results)

    def build_from_results(self, results: list[ScanResult],
                           layout_mode: str | None = None) -> None:
        """Строит топологию из результатов сканирования подсетей."""
        subnets = [r.subnet for r in results if r.subnet]

        # 1. Устройства
        for res in results:
            logger.info("Подсеть %s: %d хостов", res.subnet or "—",
                        len(res.devices))
            for host in res.devices:
                self._tag_subnets(host, res.subnet, subnets)
                self._add_or_merge_host(host)

        # 2. Мультиинтерфейсные устройства
        merged_ip = self.merge_shared_ips()
        merged_mac = self.merge_by_mac()
        if merged_ip or merged_mac:
            logger.info("Объединено устройств: по IP-алиасам %d, по MAC %d",
                        merged_ip, merged_mac)

        # 3. Шлюзы и маршрут до подсетей
        for res in results:
            if res.gateway_ip:
                gw = self.get_by_ip(res.gateway_ip)
                if gw:
                    gw.is_gateway = True
        for res in results:
            self._add_path(res, subnets)

        # 4. Явные связи от сканера (LLDP/CDP/FDB/ARP)
        for res in results:
            for ip_a, ip_b, kind, attrs in res.links:
                a, b = self.get_by_ip(ip_a), self.get_by_ip(ip_b)
                if a and b:
                    self.add_link(a.node_id, b.node_id, kind, **(attrs or {}))

        # 5. Недостающие связи
        self.infer_links()

        # 6. Метаданные и раскладка
        known = list(self.meta.get("subnets", []))
        self.meta["subnets"] = known + [s for s in subnets if s not in known]
        scanner_ips = [r.scanner_ip for r in results if r.scanner_ip]
        if scanner_ips:
            self.meta["scanner_ip"] = scanner_ips[0]
        self.meta["scanned"] = _utc_now()
        self.apply_layout(layout_mode or self.layout_mode)

    @staticmethod
    def _tag_subnets(host: Device, subnet: str, all_subnets: list[str]) -> None:
        if subnet and not host.subnet and (not host.ip
                                           or ip_in_subnet(host.ip, subnet)):
            host.subnet = subnet
        for iface in host.interfaces:
            if iface.subnet:
                continue
            if iface.ip == host.ip and host.subnet:
                iface.subnet = host.subnet
                continue
            for sn in all_subnets:
                if ip_in_subnet(iface.ip, sn):
                    iface.subnet = sn
                    break

    def _add_or_merge_host(self, host: Device) -> None:
        existing = self.get_by_ip(host.ip)
        if existing is None or existing is host:
            if existing is None:
                self.add_device(host)
            return
        _absorb(existing, host)
        for iface in host.interfaces:
            self._ip_to_id.setdefault(iface.ip, existing.node_id)

    def _add_path(self, res: ScanResult, subnets: list[str]) -> None:
        """Цепочка маршрутизаторов сканер → … → шлюз подсети."""
        prev: Device | None = None
        for idx, hop_ip in enumerate(res.path):
            if not hop_ip:
                continue
            hop = self.get_by_ip(hop_ip)
            if hop is None:
                hop_subnet = next((s for s in subnets
                                   if ip_in_subnet(hop_ip, s)), "")
                hop = Device(ip=hop_ip, device_type="router",
                             subnet=hop_subnet, hops=idx + 1,
                             notes="Обнаружен по traceroute",
                             evidence=["Промежуточный узел маршрута "
                                       "(traceroute) → router"],
                             confidence=60, last_seen=_utc_now())
                self.add_device(hop)
            else:
                if hop.device_type in ("unknown", "endpoint"):
                    hop.device_type = "router"
                    hop.evidence.append("Промежуточный узел маршрута → router")
                if hop.hops is None or hop.hops > idx + 1:
                    hop.hops = idx + 1
            if idx == 0:
                hop.is_gateway = True
            if prev is not None and prev.node_id != hop.node_id:
                self.add_link(prev.node_id, hop.node_id, "traceroute")
            prev = hop

        if prev is None:
            return
        gw = self.get_by_ip(res.gateway_ip) if res.gateway_ip else None
        if gw is None:
            gw = self._choose_gateway(res.subnet, self.subnet_members()
                                      .get(res.subnet, []))
        if gw is not None and gw.node_id != prev.node_id:
            self.add_link(prev.node_id, gw.node_id, "traceroute")
        elif gw is None:
            # Шлюз подсети не найден — подсеть «висит» на последнем хопе
            prev.notes = prev.notes or f"Маршрут к {res.subnet}"
            self.meta.setdefault("subnet_uplinks", {})[res.subnet] = prev.node_id

    # ── Вывод связей ─────────────────────────────────────────────────────────

    def _choose_gateway(self, subnet: str, members: list[str]) -> Device | None:
        devs = [self.devices[n] for n in members
                if n in self.devices and not self.devices[n].is_virtual]
        if not devs:
            return None
        flagged = [d for d in devs if d.is_gateway]
        if flagged:
            return min(flagged, key=lambda d: (d.hops or 0, ip_sort_key(d.ip)))
        routing = [d for d in devs if d.device_type in ROUTING_TYPES]
        if not routing:
            return None

        def key(d: Device) -> tuple:
            in_sn = [i.ip for i in d.interfaces if i.subnet == subnet] or [d.ip]
            edge = any(_host_index(ip, subnet) in ("first", "last")
                       for ip in in_sn)
            return (not d.is_multihomed, not edge, ip_sort_key(in_sn[0]))
        return min(routing, key=key)

    def infer_links(self) -> int:
        """
        Достраивает связи, которые не удалось получить явно:
          шлюз подсети ← коммутаторы ← конечные устройства.
        Если шлюза и коммутаторов нет — создаётся виртуальный узел-сегмент.
        Возвращает число добавленных связей.
        """
        added = 0
        uplinks: dict[str, str] = self.meta.get("subnet_uplinks", {})
        for subnet, members in self.subnet_members().items():
            member_set = set(members)
            gw = self._choose_gateway(subnet, members)
            switches = sorted(
                (self.devices[n] for n in members
                 if self.devices[n].device_type in L2_TYPES
                 and (gw is None or n != gw.node_id)),
                key=lambda d: ip_sort_key(d.ip))
            segment = next((self.devices[n] for n in members
                            if self.devices[n].is_virtual), None)

            def attached(nid: str) -> bool:
                return any(nb in member_set for nb in self.graph.neighbors(nid))

            pending = [n for n in members
                       if (gw is None or n != gw.node_id)
                       and not self.devices[n].is_virtual
                       and not attached(n)]
            if not pending:
                continue

            uplink = uplinks.get(subnet)
            root: Device | None = gw
            if root is None and switches:
                root = switches[0]
            if root is None and (len(pending) > 1 or uplink):
                if segment is None:
                    segment = self._make_segment(subnet)
                root = segment
            if root is None:
                continue
            if uplink and uplink in self.devices and uplink != root.node_id:
                self.add_link(uplink, root.node_id, "traceroute")

            for nid in pending:
                if nid == root.node_id or attached(nid):
                    continue
                dev = self.devices[nid]
                if dev.device_type in L2_TYPES | ROUTING_TYPES:
                    # Коммутаторы и прочие маршрутизаторы подсети — к шлюзу
                    parent = root
                elif len(switches) == 1:
                    # Единственный коммутатор — все устройства за ним
                    parent = switches[0]
                else:
                    # Коммутаторов несколько: неизвестно, за каким из них
                    # устройство, поэтому привязываем к шлюзу / сегменту
                    parent = root
                if parent.node_id == nid:
                    continue
                self.add_link(parent.node_id, nid, "inferred")
                added += 1
        return added

    def _make_segment(self, subnet: str) -> Device:
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            ip = str(net.network_address)
        except ValueError:
            ip = subnet
        seg = Device(ip=ip, hostname=subnet, device_type="segment",
                     subnet=subnet, is_virtual=True,
                     node_id="seg-" + uuid.uuid5(uuid.NAMESPACE_URL,
                                                 subnet).hex[:6],
                     notes="Виртуальный узел: общий L2-сегмент подсети",
                     confidence=100)
        # Сегмент не должен перехватывать IP реального устройства
        self.devices[seg.node_id] = seg
        self.graph.add_node(seg.node_id)
        return seg

    # ── Объединение ──────────────────────────────────────────────────────────

    def merge_shared_ips(self) -> int:
        """Объединяет устройства, если IP одного является интерфейсом другого
        (например, SNMP-алиасы маршрутизатора)."""
        count = 0
        changed = True
        while changed:
            changed = False
            owners: dict[str, list[str]] = {}
            for nid, dev in self.devices.items():
                if dev.is_virtual:
                    continue
                for ip in dev.all_ips():
                    owners.setdefault(ip, []).append(nid)
            for ip, nids in owners.items():
                nids = list(dict.fromkeys(nids))
                if len(nids) < 2:
                    continue
                primary = self._choose_primary(nids)
                for nid in nids:
                    if nid != primary and nid in self.devices:
                        self._merge_into(primary, nid)
                        count += 1
                        changed = True
                if changed:
                    break
        return count

    def merge_by_mac(self) -> int:
        mac_groups: dict[str, list[str]] = {}
        for nid, dev in list(self.devices.items()):
            norm = normalize_mac(dev.mac or "")
            if norm and not dev.is_virtual:
                mac_groups.setdefault(norm, []).append(nid)

        count = 0
        for norm_mac, nids in mac_groups.items():
            if len(nids) < 2:
                continue
            subnets = {self.devices[n].subnet for n in nids}
            if len(nids) > 4 and len(subnets) <= 1:
                # Много IP за одним MAC в одной подсети — это proxy-ARP
                # или NAT-шлюз, а не одно мультиинтерфейсное устройство.
                logger.warning("MAC %s отвечает за %d IP (proxy-ARP?) — "
                               "не объединяем", norm_mac, len(nids))
                for n in nids:
                    note = "Общий MAC с другими IP (proxy-ARP?)"
                    if note not in self.devices[n].notes:
                        self.devices[n].notes = (self.devices[n].notes + " "
                                                 + note).strip()
                continue
            logger.info("MAC %s → объединяем %s",
                        norm_mac, [self.devices[n].ip for n in nids])
            primary_id = self._choose_primary(nids)
            for nid in nids:
                if nid != primary_id:
                    self._merge_into(primary_id, nid)
            self.devices[primary_id].mac = norm_mac
            count += 1
        return count

    def _merge_into(self, primary_id: str, dup_id: str) -> None:
        primary = self.devices[primary_id]
        dup = self.devices[dup_id]
        _absorb(primary, dup)
        for neighbor in list(self.graph.neighbors(dup_id)):
            if neighbor != primary_id:
                attrs = dict(self.graph.edges[dup_id, neighbor])
                label = attrs.pop("label", "")
                attrs.pop("points", None)
                attrs.pop("route_src", None)
                self.add_link(primary_id, neighbor, label, **attrs)
        for ip in [ip for ip, n in self._ip_to_id.items() if n == dup_id]:
            self._ip_to_id[ip] = primary_id
        for iface in dup.interfaces:
            self._ip_to_id[iface.ip] = primary_id
        self.graph.remove_node(dup_id)
        self.devices.pop(dup_id)
        primary.is_multihomed = True

    def _choose_primary(self, nids: list[str]) -> str:
        def score(n: str) -> tuple:
            d = self.devices[n]
            info = sum(bool(x) for x in (d.hostname, d.vendor, d.os_name,
                                         d.snmp_info, d.mac))
            return (TYPE_RANK.get(d.device_type, 0), info,
                    self.graph.degree(n), -ip_sort_key(d.ip)[1])
        return max(nids, key=score)

    # ── Ручное объединение / разделение ──────────────────────────────────────

    def merge_devices(self, primary_id: str, secondary_id: str) -> bool:
        if primary_id not in self.devices or secondary_id not in self.devices:
            return False
        if primary_id == secondary_id:
            return False
        self._merge_into(primary_id, secondary_id)
        logger.info("Объединены вручную: %s ← %s",
                    self.devices[primary_id].ip, secondary_id)
        return True

    def split_device(self, node_id: str, split_ip: str) -> str | None:
        if node_id not in self.devices:
            return None
        primary = self.devices[node_id]
        iface = next((i for i in primary.interfaces if i.ip == split_ip), None)
        if not iface:
            return None
        if split_ip == primary.ip and len(primary.interfaces) <= 1:
            return None
        new_dev = Device(ip=split_ip, subnet=iface.subnet,
                         device_type=primary.device_type,
                         notes=f"Отделён от {primary.ip}")
        primary.interfaces = [i for i in primary.interfaces if i.ip != split_ip]
        if split_ip == primary.ip:
            primary.ip = primary.interfaces[0].ip
            primary.subnet = primary.interfaces[0].subnet
        self._ip_to_id.pop(split_ip, None)
        self.add_device(new_dev)
        subnets = {i.subnet for i in primary.interfaces if i.subnet}
        primary.is_multihomed = len(primary.interfaces) > 1 or len(subnets) > 1
        logger.info("Разделение: %s → новый %s (%s)",
                    node_id, new_dev.node_id, split_ip)
        return new_dev.node_id

    # ── Раскладка ────────────────────────────────────────────────────────────

    def apply_layout(self, mode: str = "tree") -> None:
        """Пересчитывает позиции узлов и маршруты связей (layout.py)."""
        from layout import compute_layout
        if not self.devices:
            return
        self.layout_mode = mode
        positions, routes = compute_layout(self, mode)
        for nid, pos in positions.items():
            if nid in self.devices:
                self.devices[nid].position = pos
        for u, v, data in self.graph.edges(data=True):
            for key in ROUTE_KEYS:
                data.pop(key, None)
        for (src, dst), pts in routes.items():
            if self.graph.has_edge(src, dst):
                data = self.graph.edges[src, dst]
                data["points"] = [list(p) for p in pts]
                data["route_src"] = src
                data["route_at"] = [list(self.devices[src].position),
                                    list(self.devices[dst].position)]

    def _assign_positions(self) -> None:
        """Обратная совместимость."""
        self.apply_layout(self.layout_mode)

    def edge_route(self, src: str, dst: str) -> list[tuple[float, float]]:
        """
        Ломаная связи src → dst. Если узлы сдвинуты после раскладки,
        сохранённый маршрут недействителен — возвращается прямая.
        """
        a, b = self.devices.get(src), self.devices.get(dst)
        if not a or not b or not a.position or not b.position:
            return []
        data = self.graph.edges[src, dst] if self.graph.has_edge(src, dst) else {}
        pts = data.get("points")
        route_src = data.get("route_src", src)
        if pts and len(pts) >= 2 and route_src in (src, dst):
            first, last = (a, b) if route_src == src else (b, a)
            snap = data.get("route_at")
            route = None
            if snap and len(snap) == 2:
                moved_first = not _same_point(snap[0], first.position)
                moved_last = not _same_point(snap[1], last.position)
                if not (moved_first or moved_last):
                    route = [(float(p[0]), float(p[1])) for p in pts]
                else:
                    # Узел сдвинут вручную — подключаем его к шине уровня,
                    # чтобы связь не превратилась в диагональ через схему
                    from layout import reanchor_route
                    route = reanchor_route(
                        pts, first.position if moved_first else None,
                        last.position if moved_last else None)
            else:
                from layout import route_is_valid
                if route_is_valid(pts, first.position, last.position):
                    route = [(float(p[0]), float(p[1])) for p in pts]
            if route:
                return route if route_src == src else list(reversed(route))
        return self._fallback_route(a.position, b.position)

    def _fallback_route(self, pa: tuple[float, float],
                        pb: tuple[float, float]) -> list[tuple[float, float]]:
        """
        Маршрут для связи без сохранённой ломаной (добавлена вручную,
        перенесена при объединении узлов). В режимах дерева — ортогональная
        «оргсхема»: вниз от верхнего узла до шины, по шине, вниз к нижнему.
        """
        from layout import LANE_GAP_LR, LANE_GAP_TB, NODE_H, NODE_W
        if self.layout_mode == "tree-lr":
            # Та же логика в повёрнутых осях
            pts = _org_route((pa[1], pa[0]), (pb[1], pb[0]), NODE_W / 2,
                             NODE_H / 2, LANE_GAP_LR)
            return [(y, x) for x, y in pts] if pts else [pa, pb]
        if self.layout_mode == "tree":
            return _org_route(pa, pb, NODE_H / 2, NODE_W / 2,
                              LANE_GAP_TB) or [pa, pb]
        return [pa, pb]

    def clear_route(self, src: str, dst: str) -> None:
        if self.graph.has_edge(src, dst):
            for key in ROUTE_KEYS:
                self.graph.edges[src, dst].pop(key, None)

    # ── Сериализация ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        links = []
        for s, d, a in self.links:
            item = {"src": s, "dst": d, "label": a.get("label", "")}
            for key in ("local_port", "remote_port") + ROUTE_KEYS:
                if a.get(key):
                    item[key] = a[key]
            links.append(item)
        return {
            "format":    FILE_FORMAT,
            "version":   FILE_VERSION,
            "generator": f"{APP_NAME} {APP_VERSION}",
            "saved":     _utc_now(),
            "meta":      self.meta,
            "layout":    self.layout_mode,
            "devices":   [dev.to_dict() for dev in self.devices.values()],
            "links":     links,
        }

    def load_dict(self, data: dict[str, Any]) -> None:
        self.graph.clear()
        self.devices.clear()
        self._ip_to_id.clear()
        self.meta = dict(data.get("meta", {}) or {})
        self.layout_mode = data.get("layout", "tree") or "tree"

        raw = data.get("devices", {})
        if isinstance(raw, dict):            # формат v1: {node_id: device}
            items = []
            for nid, dd in raw.items():
                dd = dict(dd)
                dd["node_id"] = nid
                items.append(dd)
        else:
            items = list(raw)
        for dd in items:
            dev = Device.from_dict(dd)
            self.add_device(dev)
        self.reindex()
        for lnk in data.get("links", []):
            src, dst = lnk.get("src"), lnk.get("dst")
            if src not in self.devices or dst not in self.devices:
                continue
            attrs = {k: lnk[k] for k in ("local_port", "remote_port")
                     if lnk.get(k)}
            self.add_link(src, dst, lnk.get("label", ""), **attrs)
            if lnk.get("points") and self.graph.has_edge(src, dst):
                data = self.graph.edges[src, dst]
                for key in ROUTE_KEYS:
                    if lnk.get(key):
                        data[key] = lnk[key]
                data.setdefault("route_src", src)
        self.place_missing()

    def place_missing(self) -> int:
        """
        Расставляет узлы без координат, не трогая остальные: если позиций нет
        ни у кого — полная раскладка, иначе свободные ячейки справа от схемы.
        """
        missing = [d for d in self.devices.values() if d.position is None]
        if not missing:
            return 0
        if len(missing) == len(self.devices):
            self.apply_layout(self.layout_mode)
            return len(missing)
        from layout import NODE_H, NODE_W, layout_bounds
        placed = {n: d.position for n, d in self.devices.items() if d.position}
        _x0, y0, x1, _y1 = layout_bounds(placed)
        step_x, step_y = NODE_W + 64, NODE_H + 30
        cols = max(1, int(len(missing) ** 0.5))
        for i, dev in enumerate(missing):
            dev.position = (x1 + 80 + NODE_W / 2 + (i % cols) * step_x,
                            y0 + NODE_H / 2 + (i // cols) * step_y)
        return len(missing)

    def save_json(self, path: str) -> None:
        """Атомарная запись: сначала во временный файл, затем замена."""
        path = os.fspath(path)
        directory = os.path.dirname(os.path.abspath(path))
        fd, tmp = tempfile.mkstemp(prefix=".topology-", suffix=".tmp",
                                   dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        logger.info("Сохранено → %s", path)

    def load_json(self, path: str) -> None:
        with open(path, encoding="utf-8-sig") as f:
            data = json.load(f)
        if not isinstance(data, dict) or "devices" not in data:
            raise ValueError("Файл не похож на топологию Net Topology")
        self.load_dict(data)
        logger.info("Загружено ← %s (%d устройств)", path, len(self.devices))

    def export_graphml(self, path: str) -> None:
        from exporters import export_graphml
        export_graphml(self, path)


# ─── Вспомогательные функции ─────────────────────────────────────────────────

def _absorb(primary: Device, other: Device) -> None:
    """Переносит сведения other → primary, не затирая уже известное."""
    for iface in other.interfaces:
        primary.add_interface(iface.ip, iface.subnet, iface.iface_name)
    for attr in ("mac", "hostname", "vendor", "ttl", "os_name", "os_family",
                 "model", "netbios_name", "workgroup", "hops", "location",
                 "last_seen"):
        if not getattr(primary, attr) and getattr(other, attr):
            setattr(primary, attr, getattr(other, attr))
    if primary.device_type == "unknown" and other.device_type != "unknown":
        primary.device_type = other.device_type
        primary.confidence = other.confidence
    for p in other.open_ports:
        if p not in primary.open_ports:
            primary.open_ports.append(p)
    primary.open_ports.sort()
    for k, v in other.services.items():
        primary.services.setdefault(k, v)
    for k, v in other.snmp_info.items():
        primary.snmp_info.setdefault(k, v)
    for e in other.evidence:
        if e not in primary.evidence:
            primary.evidence.append(e)
    primary.is_gateway = primary.is_gateway or other.is_gateway
    primary.is_scanner = primary.is_scanner or other.is_scanner
    if other.notes and other.notes not in primary.notes:
        primary.notes = (primary.notes + " " + other.notes).strip()


def _org_route(pa: tuple[float, float], pb: tuple[float, float],
               half_depth: float, half_breadth: float, lane_gap: float
               ) -> list[tuple[float, float]] | None:
    """
    Ортогональная связь в осях «дерево сверху вниз»: от верхнего узла вниз
    до шины, затем либо прямо вниз (узел в первом ряду под шиной), либо
    «гребёнкой» по зазору слева от столбца с входом в карточку сбоку —
    чтобы линия не шла за карточками верхних рядов.

    half_depth / half_breadth — половины высоты / ширины карточки,
    lane_gap — расстояние от края карточки до «гребёнки».
    None — узлы на одном уровне (тогда рисуется прямая).
    """
    upper, lower = (pa, pb) if pa[1] <= pb[1] else (pb, pa)
    gap = (lower[1] - half_depth) - (upper[1] + half_depth)
    if gap < 20:
        return None
    bus = upper[1] + half_depth + min(50.0, gap / 2)
    start = (upper[0], upper[1] + half_depth)
    if (lower[1] - half_depth) - bus <= 60:
        pts = [start, (upper[0], bus), (lower[0], bus),
               (lower[0], lower[1] - half_depth)]
    else:
        side = lower[0] - half_breadth          # левый край карточки
        lane = side - lane_gap
        pts = [start, (upper[0], bus), (lane, bus), (lane, lower[1]),
               (side, lower[1])]
    from layout import _simplify
    pts = _simplify(pts)
    return pts if upper is pa else list(reversed(pts))


def _same_point(a, b, tol: float = 0.5) -> bool:
    try:
        return abs(float(a[0]) - b[0]) <= tol and abs(float(a[1]) - b[1]) <= tol
    except (TypeError, IndexError, ValueError):
        return False


def _host_index(ip: str, subnet: str) -> str:
    """'first' / 'last' если IP — первый/последний адрес хоста подсети."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if addr not in net or net.num_addresses < 4:
        return ""
    if int(addr) == int(net.network_address) + 1:
        return "first"
    if int(addr) == int(net.broadcast_address) - 1:
        return "last"
    return ""


def _subnet_key(subnet: str) -> tuple:
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        return (0, int(net.network_address), net.prefixlen)
    except ValueError:
        return (1, 0, 0)
