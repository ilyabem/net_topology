"""
model.py — модель данных топологии сети.

ТИПЫ УСТРОЙСТВ (расширены):
  Сетевое оборудование : router, switch, bridge, firewall
  Серверы              : windows_server, linux_server, server
  Конечные точки       : windows_endpoint, linux_endpoint, printer, voip_phone, mobile_device, endpoint
  Не определено        : unknown

MULTI-HOMED поддержка:
  - Interface — один IP + подсеть + имя порта
  - Device.interfaces — все интерфейсы устройства
  - Device.is_multihomed — флаг
  - normalize_mac() — нормализация MAC в AA:BB:CC:DD:EE:FF
  - NetworkTopology.build_from_multi_subnet()
  - NetworkTopology.merge_by_mac() / merge_devices() / split_device()
"""

from __future__ import annotations

import json
import logging
import math
import re
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any

import networkx as nx

logger = logging.getLogger("model")

# ─── Типы устройств ──────────────────────────────────────────────────────────

DEVICE_TYPES = [
    "router",
    "switch",
    "bridge",
    "firewall",
    "windows_server",
    "linux_server",
    "server",
    "windows_endpoint",
    "linux_endpoint",
    "printer",
    "voip_phone",      # VoIP-телефон / IP-АТС
    "mobile_device",   # мобильное устройство (Android / iOS / другое)
    "endpoint",
    "unknown",
]

# Человекочитаемые метки для GUI (тип → метка)
DEVICE_TYPE_LABELS: dict[str, str] = {
    "router":           "Маршрутизатор",
    "switch":           "Коммутатор",
    "bridge":           "Бридж",
    "firewall":         "Межсетевой экран",
    "windows_server":   "Windows Server",
    "linux_server":     "Linux Server",
    "server":           "Сервер",
    "windows_endpoint": "Windows ПК",
    "linux_endpoint":   "Linux/macOS ПК",
    "printer":          "Принтер/МФУ",
    "voip_phone":      "VoIP-телефон",
    "mobile_device":   "Мобильное устройство",
    "endpoint":         "Конечная точка",
    "unknown":          "Неизвестно",
}

# Группы типов для фильтра в GUI
DEVICE_TYPE_GROUPS: dict[str, list[str]] = {
    "🔴 Сетевое оборудование": ["router", "switch", "bridge", "firewall"],
    "🟢 Серверы":              ["windows_server", "linux_server", "server"],
    "⚫ Конечные точки":       ["windows_endpoint", "linux_endpoint",
                                "printer", "voip_phone", "endpoint"],
    "📱 Мобильные":            ["mobile_device"],
    "⬜ Неизвестные":          ["unknown"],
}

TYPE_COLORS: dict[str, str] = {
    "router":           "#e74c3c",   # красный
    "switch":           "#2980b9",   # синий
    "bridge":           "#8e44ad",   # фиолетовый
    "firewall":         "#e67e22",   # оранжевый
    "windows_server":   "#16a085",   # бирюзовый
    "linux_server":     "#27ae60",   # зелёный
    "server":           "#1abc9c",   # светло-бирюзовый
    "windows_endpoint": "#2c3e50",   # тёмно-синий
    "linux_endpoint":   "#7f8c8d",   # серый
    "printer":          "#f39c12",   # жёлтый
    "voip_phone":      "#00bcd4",   # голубой
    "mobile_device":   "#78909c",   # серо-синий
    "endpoint":         "#95a5a6",   # светло-серый
    "unknown":          "#bdc3c7",   # очень светлый серый
}

TYPE_SHAPES: dict[str, str] = {
    "router":           "diamond",
    "switch":           "square",
    "bridge":           "hexagon",
    "firewall":         "triangle",
    "windows_server":   "circle",
    "linux_server":     "circle",
    "server":           "circle",
    "windows_endpoint": "circle",
    "linux_endpoint":   "circle",
    "printer":          "square",
    "voip_phone":      "hexagon",
    "mobile_device":   "circle",
    "endpoint":         "circle",
    "unknown":          "circle",
}


# ─── Нормализация MAC ────────────────────────────────────────────────────────

def normalize_mac(mac: str) -> str:
    """
    Приводит MAC к формату AA:BB:CC:DD:EE:FF.
    Поддерживает: aa:bb:cc:dd:ee:ff / AA-BB-CC-DD-EE-FF /
                  aabb.ccdd.eeff / aabbccddeeff
    Возвращает '' если формат не распознан.
    """
    if not mac:
        return ""
    clean = re.sub(r"[:\-\.]", "", mac).upper()
    if len(clean) != 12 or not re.fullmatch(r"[0-9A-F]{12}", clean):
        return ""
    return ":".join(clean[i:i+2] for i in range(0, 12, 2))


# ─── Interface ───────────────────────────────────────────────────────────────

@dataclass
class Interface:
    """Один сетевой интерфейс: IP + подсеть CIDR + имя порта."""
    ip: str
    subnet: str = ""
    iface_name: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"ip": self.ip, "subnet": self.subnet, "iface_name": self.iface_name}

    @classmethod
    def from_dict(cls, d: dict) -> "Interface":
        return cls(ip=d.get("ip", ""),
                   subnet=d.get("subnet", ""),
                   iface_name=d.get("iface_name", ""))


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
    node_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    position: tuple[float, float] | None = None
    notes: str = ""
    subnet: str = ""
    interfaces: list[Interface] = field(default_factory=list)
    is_multihomed: bool = False

    def __post_init__(self) -> None:
        # Добавляем основной IP в список интерфейсов если его там нет
        if self.ip and not any(i.ip == self.ip for i in self.interfaces):
            self.interfaces.append(Interface(ip=self.ip, subnet=self.subnet))

    def add_interface(self, ip: str, subnet: str = "", iface_name: str = "") -> None:
        """Добавить интерфейс без дублирования."""
        if not any(i.ip == ip for i in self.interfaces):
            self.interfaces.append(Interface(ip=ip, subnet=subnet,
                                             iface_name=iface_name))

    def all_ips(self) -> list[str]:
        return [i.ip for i in self.interfaces]

    def interfaces_label(self) -> str:
        lines = []
        for i in self.interfaces:
            n = f" ({i.iface_name})" if i.iface_name else ""
            s = f" [{i.subnet}]"     if i.subnet     else ""
            lines.append(f"{i.ip}{n}{s}")
        return "\n".join(lines)

    def label(self) -> str:
        name = self.hostname or self.ip
        lbl  = DEVICE_TYPE_LABELS.get(self.device_type, self.device_type)
        if self.is_multihomed:
            return f"★ {name}\n[{lbl}]\n{self.interfaces_label()}"
        return f"{name}\n[{lbl}]"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["interfaces"] = [i.to_dict() for i in self.interfaces]
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Device":
        if data.get("position") and not isinstance(data["position"], tuple):
            data["position"] = tuple(data["position"])
        raw_ifaces = data.pop("interfaces", [])
        obj = cls(**data)
        # Восстанавливаем интерфейсы (избегаем дубля с __post_init__)
        obj.interfaces = []
        for i in raw_ifaces:
            iface = Interface.from_dict(i) if isinstance(i, dict) else i
            if not any(x.ip == iface.ip for x in obj.interfaces):
                obj.interfaces.append(iface)
        # Убеждаемся что основной IP есть
        if obj.ip and not any(x.ip == obj.ip for x in obj.interfaces):
            obj.interfaces.insert(0, Interface(ip=obj.ip, subnet=obj.subnet))
        return obj


# ─── NetworkTopology ─────────────────────────────────────────────────────────

class NetworkTopology:
    """
    Хранилище топологии: граф NetworkX + словарь устройств.

    Ключевые методы:
      build_from_hosts()          — одна подсеть (обратная совместимость)
      build_from_multi_subnet()   — несколько подсетей
      merge_by_mac()              — авто-объединение по MAC
      merge_devices()             — ручное объединение
      split_device()              — ручное разделение
    """

    def __init__(self) -> None:
        self.graph: nx.Graph = nx.Graph()
        self.devices: dict[str, Device] = {}
        self._ip_to_id: dict[str, str] = {}

    # ── CRUD ─────────────────────────────────────────────────────────────────

    def add_device(self, device: Device) -> str:
        nid = device.node_id
        self.devices[nid] = device
        self._ip_to_id[device.ip] = nid
        for iface in device.interfaces:
            self._ip_to_id[iface.ip] = nid
        self.graph.add_node(nid)
        return nid

    def remove_device(self, node_id: str) -> None:
        if node_id not in self.devices:
            return
        dev = self.devices.pop(node_id)
        self._ip_to_id.pop(dev.ip, None)
        for iface in dev.interfaces:
            self._ip_to_id.pop(iface.ip, None)
        if self.graph.has_node(node_id):
            self.graph.remove_node(node_id)

    def get_by_ip(self, ip: str) -> Device | None:
        nid = self._ip_to_id.get(ip)
        return self.devices.get(nid) if nid else None

    def add_link(self, src: str, dst: str, label: str = "") -> None:
        if src != dst and not self.graph.has_edge(src, dst):
            if self.graph.has_node(src) and self.graph.has_node(dst):
                self.graph.add_edge(src, dst, label=label)

    def remove_link(self, src: str, dst: str) -> None:
        if self.graph.has_edge(src, dst):
            self.graph.remove_edge(src, dst)

    @property
    def links(self) -> list[tuple[str, str, dict]]:
        return list(self.graph.edges(data=True))

    # ── Построение топологии ─────────────────────────────────────────────────

    def build_from_hosts(
        self,
        hosts: list[Device],
        arp_table: dict[str, list[tuple[str, str]]] | None = None,
        subnet: str = "",
    ) -> None:
        """Одна подсеть — обратная совместимость."""
        for host in hosts:
            if subnet and not host.subnet:
                host.subnet = subnet
                if host.interfaces:
                    host.interfaces[0].subnet = subnet
        self._add_hosts_and_links(hosts, arp_table)
        self._assign_positions()

    def build_from_multi_subnet(
        self,
        subnet_results: list[
            tuple[str, list[Device], dict[str, list[tuple[str, str]]] | None]
        ],
    ) -> None:
        """Несколько подсетей: добавляем хосты → merge_by_mac → позиции."""
        for subnet, hosts, arp_table in subnet_results:
            logger.info("Подсеть %s: %d хостов", subnet, len(hosts))
            for host in hosts:
                if not host.subnet:
                    host.subnet = subnet
                for iface in host.interfaces:
                    if not iface.subnet:
                        iface.subnet = subnet
            self._add_hosts_and_links(hosts, arp_table)

        merged = self.merge_by_mac()
        logger.info("Объединено по MAC: %d групп", merged)
        self._add_intersubnet_links()
        self._assign_positions()

    def _add_hosts_and_links(
        self,
        hosts: list[Device],
        arp_table: dict[str, list[tuple[str, str]]] | None,
    ) -> None:
        for host in hosts:
            existing = self.get_by_ip(host.ip)
            if existing:
                for iface in host.interfaces:
                    existing.add_interface(iface.ip, iface.subnet, iface.iface_name)
            else:
                self.add_device(host)

        if arp_table:
            for gw_ip, entries in arp_table.items():
                gw = self.get_by_ip(gw_ip)
                if not gw:
                    continue
                for ip, _ in entries:
                    peer = self.get_by_ip(ip)
                    if peer:
                        self.add_link(gw.node_id, peer.node_id, label="ARP")
        else:
            hub = self._find_hub()
            if hub:
                for nid in list(self.devices):
                    if nid != hub.node_id:
                        self.add_link(hub.node_id, nid, label="heuristic")

    def _find_hub(self) -> Device | None:
        for ptype in ["router", "firewall", "switch", "bridge"]:
            for dev in self.devices.values():
                if dev.device_type == ptype:
                    return dev
        return next(iter(self.devices.values()), None)

    # ── Merge by MAC ─────────────────────────────────────────────────────────

    def merge_by_mac(self) -> int:
        """
        Находит узлы с одинаковым нормализованным MAC, объединяет их.
        Возвращает число объединённых групп.
        """
        mac_groups: dict[str, list[str]] = {}
        for nid, dev in list(self.devices.items()):
            if not dev.mac:
                continue
            norm = normalize_mac(dev.mac)
            if norm:
                mac_groups.setdefault(norm, []).append(nid)

        count = 0
        for norm_mac, nids in mac_groups.items():
            if len(nids) < 2:
                continue
            logger.info("MAC %s → объединяем %s",
                        norm_mac, [self.devices[n].ip for n in nids])
            primary_id = self._choose_primary(nids)
            primary    = self.devices[primary_id]

            for nid in nids:
                if nid == primary_id:
                    continue
                dup = self.devices[nid]
                for iface in dup.interfaces:
                    primary.add_interface(iface.ip, iface.subnet, iface.iface_name)
                for neighbor in list(self.graph.neighbors(nid)):
                    if neighbor != primary_id:
                        attrs = self.graph.edges[nid, neighbor]
                        self.add_link(primary_id, neighbor, attrs.get("label", ""))
                for iface in dup.interfaces:
                    self._ip_to_id[iface.ip] = primary_id
                self._ip_to_id.pop(dup.ip, None)
                self.graph.remove_node(nid)
                self.devices.pop(nid)

            primary.is_multihomed = True
            primary.mac = norm_mac
            count += 1
        return count

    def _choose_primary(self, nids: list[str]) -> str:
        priority = {
            "router": 8, "firewall": 7, "switch": 6, "bridge": 5,
            "windows_server": 4, "linux_server": 4, "server": 3,
            "windows_endpoint": 2, "linux_endpoint": 2,
            "printer": 2, "voip_phone": 2,
            "mobile_device": 1, "endpoint": 1, "unknown": 0,
        }
        return max(nids, key=lambda n: (
            priority.get(self.devices[n].device_type, 0),
            self.graph.degree(n),
        ))

    def _add_intersubnet_links(self) -> None:
        for nid, dev in list(self.devices.items()):
            if not dev.is_multihomed:
                continue
            gw_subnets = {i.subnet for i in dev.interfaces if i.subnet}
            for other_id, other in self.devices.items():
                if other_id == nid:
                    continue
                other_subnets = {i.subnet for i in other.interfaces if i.subnet}
                if gw_subnets & other_subnets:
                    self.add_link(nid, other_id, label="inter-subnet")

    # ── Ручное объединение / разделение ──────────────────────────────────────

    def merge_devices(self, primary_id: str, secondary_id: str) -> bool:
        if primary_id not in self.devices or secondary_id not in self.devices:
            return False
        if primary_id == secondary_id:
            return False
        primary   = self.devices[primary_id]
        secondary = self.devices[secondary_id]
        for iface in secondary.interfaces:
            primary.add_interface(iface.ip, iface.subnet, iface.iface_name)
        for neighbor in list(self.graph.neighbors(secondary_id)):
            if neighbor != primary_id:
                attrs = self.graph.edges[secondary_id, neighbor]
                self.add_link(primary_id, neighbor, attrs.get("label", "manual"))
        for iface in secondary.interfaces:
            self._ip_to_id[iface.ip] = primary_id
        self._ip_to_id.pop(secondary.ip, None)
        self.graph.remove_node(secondary_id)
        self.devices.pop(secondary_id)
        primary.is_multihomed = True
        logger.info("Объединены вручную: %s ← %s", primary.ip, secondary.ip)
        return True

    def split_device(self, node_id: str, split_ip: str) -> str | None:
        if node_id not in self.devices:
            return None
        primary = self.devices[node_id]
        iface   = next((i for i in primary.interfaces if i.ip == split_ip), None)
        if not iface:
            return None
        if split_ip == primary.ip and len(primary.interfaces) <= 1:
            return None
        new_dev = Device(ip=split_ip, subnet=iface.subnet,
                         device_type=primary.device_type,
                         notes=f"Отделён от {primary.ip}")
        self.add_device(new_dev)
        primary.interfaces = [i for i in primary.interfaces if i.ip != split_ip]
        self._ip_to_id.pop(split_ip, None)
        subnets = {i.subnet for i in primary.interfaces if i.subnet}
        primary.is_multihomed = len(subnets) > 1
        logger.info("Разделение: %s → новый %s (%s)", node_id, new_dev.node_id, split_ip)
        return new_dev.node_id

    # ── Позиции ──────────────────────────────────────────────────────────────

    def _assign_positions(self) -> None:
        """
        Назначает координаты узлам.
        Адаптивный canvas + принудительное разведение перекрывающихся узлов.
        """
        if not self.graph.nodes:
            return

        n = len(self.graph.nodes)
        # Адаптивный canvas: 90px на узел, минимум 800x600
        side   = max(800, int(90 * math.sqrt(n)))
        width  = side
        height = int(side * 0.75)
        margin = 80
        MIN_DIST = 72  # минимум между центрами (2.5 * NODE_RADIUS=28)

        # k масштабируется под плотность
        k_val = max(1.5, 3.0 / math.sqrt(max(n, 1)))

        try:
            pos = nx.spring_layout(self.graph, seed=42, k=k_val,
                                   iterations=100)
        except Exception:
            nodes = list(self.graph.nodes)
            hub   = max(nodes,
                        key=lambda nd: self.graph.degree(nd),
                        default=nodes[0])
            others = [nd for nd in nodes if nd != hub]
            pos = {hub: (0.0, 0.0)}
            rings    = max(1, math.ceil(math.sqrt(len(others))))
            per_ring = max(1, math.ceil(len(others) / rings))
            for i, nd in enumerate(others):
                ring  = i // per_ring + 1
                angle = 2 * math.pi * (i % per_ring) / per_ring
                pos[nd] = (ring * math.cos(angle) / rings,
                           ring * math.sin(angle) / rings)

        # Нормализуем в пиксели
        xs    = [p[0] for p in pos.values()]
        ys    = [p[1] for p in pos.values()]
        xspan = max(max(xs) - min(xs), 1e-6)
        yspan = max(max(ys) - min(ys), 1e-6)

        pixel_pos: dict[str, tuple[float, float]] = {}
        for nid, (x, y) in pos.items():
            px = margin + (x - min(xs)) / xspan * (width  - 2 * margin)
            py = margin + (y - min(ys)) / yspan * (height - 2 * margin)
            pixel_pos[nid] = (px, py)

        # Разводим перекрывающиеся узлы
        pixel_pos = self._spread_overlapping(
            pixel_pos, MIN_DIST, width, height, margin)

        for nid, (px, py) in pixel_pos.items():
            if nid in self.devices:
                self.devices[nid].position = (px, py)

    @staticmethod
    def _spread_overlapping(
        positions: dict[str, tuple[float, float]],
        min_dist: float,
        width: float,
        height: float,
        margin: float,
        max_passes: int = 60,
    ) -> dict[str, tuple[float, float]]:
        """
        Итеративно отталкивает пары узлов ближе min_dist.
        O(n^2 * passes) — приемлемо до ~500 узлов.
        """
        pos   = {nid: list(p) for nid, p in positions.items()}
        nodes = list(pos.keys())

        for _ in range(max_passes):
            moved = False
            for i in range(len(nodes)):
                for j in range(i + 1, len(nodes)):
                    a, b = nodes[i], nodes[j]
                    dx   = pos[b][0] - pos[a][0]
                    dy   = pos[b][1] - pos[a][1]
                    dist = math.sqrt(dx * dx + dy * dy)
                    if dist < min_dist and dist > 1e-6:
                        push  = (min_dist - dist) / 2.0 + 1.0
                        nx_   = dx / dist * push
                        ny_   = dy / dist * push
                        pos[a][0] -= nx_
                        pos[a][1] -= ny_
                        pos[b][0] += nx_
                        pos[b][1] += ny_
                        moved = True
            if not moved:
                break

        # Прижимаем к границам
        for nid in pos:
            pos[nid][0] = max(margin, min(width  - margin, pos[nid][0]))
            pos[nid][1] = max(margin, min(height - margin, pos[nid][1]))

        return {nid: (p[0], p[1]) for nid, p in pos.items()}

    # ── Сериализация ─────────────────────────────────────────────────────────

    def save_json(self, path: str) -> None:
        data = {
            "devices": {nid: dev.to_dict()
                        for nid, dev in self.devices.items()},
            "links":   [{"src": s, "dst": d, "label": a.get("label", "")}
                        for s, d, a in self.links],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info("Сохранено → %s", path)

    def load_json(self, path: str) -> None:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.graph.clear()
        self.devices.clear()
        self._ip_to_id.clear()
        for nid, dd in data.get("devices", {}).items():
            dev = Device.from_dict(dd)
            dev.node_id = nid
            self.add_device(dev)
        for lnk in data.get("links", []):
            self.add_link(lnk["src"], lnk["dst"], lnk.get("label", ""))
        logger.info("Загружено ← %s (%d устройств)", path, len(self.devices))

    def export_graphml(self, path: str) -> None:
        for nid, dev in self.devices.items():
            self.graph.nodes[nid]["ip"]         = dev.ip
            self.graph.nodes[nid]["all_ips"]    = ",".join(dev.all_ips())
            self.graph.nodes[nid]["type"]       = dev.device_type
            self.graph.nodes[nid]["label"]      = dev.hostname or dev.ip
            self.graph.nodes[nid]["multihomed"] = str(dev.is_multihomed)
        nx.write_graphml(self.graph, path)
        logger.info("GraphML → %s", path)
