"""
visual.py — единый внешний вид схемы для GUI и экспорта (SVG/HTML/draw.io).

  * Векторные иконки типов устройств (SVG 48×48, белый глиф на цветной плитке).
  * Содержимое карточки узла: заголовок, IP, строка «производитель · ОС».
  * Бейджи (шлюз, мультиинтерфейсное, RDP/SSH/…).
  * Стили связей и цвета зон подсетей.
"""

from __future__ import annotations

import hashlib
import colorsys
from dataclasses import dataclass
from typing import TYPE_CHECKING

from layout import NODE_H, NODE_W
from model import (DEVICE_TYPE_LABELS, LINK_LABELS, TYPE_COLORS,
                   ip_sort_key)

if TYPE_CHECKING:
    from model import Device, NetworkTopology

# ─── Геометрия карточки (смещения от верхнего левого угла) ───────────────────
ICON_SIZE = 44.0
ICON_TOP = 8.0
TITLE_Y = 68.0       # базовые линии текста
IP_Y = 83.0
DETAIL_Y = 97.0
TITLE_CHARS = 22     # ограничения длины строк для экспорта без метрик шрифта
IP_CHARS = 24
DETAIL_CHARS = 27
BADGE_W = 30.0
BADGE_H = 14.0

FONT_FAMILY = "Segoe UI, Roboto, Helvetica, Arial, sans-serif"

# ─── Иконки ──────────────────────────────────────────────────────────────────
# Глифы рисуются белой линией поверх цветной плитки 48×48.
_GLYPHS: dict[str, str] = {
    "router": (
        '<circle cx="24" cy="24" r="13"/>'
        '<path d="M24 14v20M14 24h20M24 14l-3 3M24 14l3 3M24 34l-3-3'
        'M24 34l3-3M14 24l3-3M14 24l3 3M34 24l-3-3M34 24l-3 3"/>'),
    "firewall": (
        '<rect x="10" y="12" width="28" height="24" rx="2"/>'
        '<path d="M10 20h28M10 28h28M19 12v8M29 12v8M15 20v8M24 20v8'
        'M33 20v8M19 28v8M29 28v8"/>'),
    "switch": (
        '<rect x="8" y="15" width="32" height="18" rx="3"/>'
        '<path d="M14 21h16l-3-3M34 27H18l3 3"/>'),
    "bridge": (
        '<path d="M8 32h32M12 32v-6a12 12 0 0 1 24 0v6M18 32v-5M24 32v-7'
        'M30 32v-5"/>'),
    "access_point": (
        '<path d="M14 21a14 14 0 0 1 20 0M18 25a8 8 0 0 1 12 0"/>'
        '<circle cx="24" cy="29" r="1.8" fill="#fff"/>'
        '<rect x="12" y="34" width="24" height="5" rx="2"/>'),
    "server": (
        '<rect x="12" y="9" width="24" height="9" rx="2"/>'
        '<rect x="12" y="20" width="24" height="9" rx="2"/>'
        '<rect x="12" y="31" width="24" height="9" rx="2"/>'
        '<path d="M17 13.5h2M17 24.5h2M17 35.5h2M27 13.5h4M27 24.5h4'
        'M27 35.5h4"/>'),
    "nas": (
        '<ellipse cx="24" cy="13" rx="12" ry="4"/>'
        '<path d="M12 13v22c0 2.2 5.4 4 12 4s12-1.8 12-4V13'
        'M12 24c0 2.2 5.4 4 12 4s12-1.8 12-4"/>'),
    "endpoint": (
        '<rect x="9" y="11" width="30" height="20" rx="2"/>'
        '<path d="M20 37h8M24 31v6"/>'),
    "laptop": (
        '<rect x="12" y="13" width="24" height="16" rx="2"/>'
        '<path d="M8 35h32l-3-6H11z"/>'),
    "printer": (
        '<path d="M16 18V10h16v8"/>'
        '<rect x="9" y="18" width="30" height="13" rx="2"/>'
        '<path d="M16 27h16v11H16z"/>'),
    "voip_phone": (
        '<path d="M15 11c-2 0-4 2-4 4 0 12 10 22 22 22 2 0 4-2 4-4v-3'
        'l-6-3-3 3c-4-2-8-6-10-10l3-3-3-6z"/>'),
    "ip_camera": (
        '<rect x="8" y="16" width="22" height="14" rx="3"/>'
        '<path d="M30 20l9-4v14l-9-4"/><circle cx="19" cy="23" r="3.5"/>'),
    "iot": (
        '<rect x="15" y="15" width="18" height="18" rx="2"/>'
        '<path d="M20 15v-5M28 15v-5M20 38v-5M28 38v-5M15 20h-5M15 28h-5'
        'M38 20h-5M38 28h-5"/>'),
    "mobile_device": (
        '<rect x="16" y="8" width="16" height="32" rx="3"/>'
        '<path d="M22 35h4"/>'),
    "segment": (
        '<path d="M15 33h19a7 7 0 0 0 1-14 10 10 0 0 0-19-2 8 8 0 0 0-1 16z"/>'),
    "unknown": (
        '<path d="M18 18a6 6 0 1 1 9 5c-2 1-3 2-3 4v2"/>'
        '<circle cx="24" cy="34" r="1.8" fill="#fff"/>'),
}

_GLYPH_FOR_TYPE: dict[str, str] = {
    "windows_server": "server", "linux_server": "server", "server": "server",
    "windows_endpoint": "endpoint", "linux_endpoint": "laptop",
}


def type_color(device_type: str) -> str:
    return TYPE_COLORS.get(device_type, TYPE_COLORS["unknown"])


def icon_inner(device_type: str) -> str:
    """Содержимое иконки (без корневого <svg>) в системе координат 48×48."""
    glyph = _GLYPHS.get(_GLYPH_FOR_TYPE.get(device_type, device_type),
                        _GLYPHS["unknown"])
    return (f'<rect x="0" y="0" width="48" height="48" rx="11" '
            f'fill="{type_color(device_type)}"/>'
            f'<g fill="none" stroke="#fff" stroke-width="2.6" '
            f'stroke-linecap="round" stroke-linejoin="round">{glyph}</g>')


def icon_svg(device_type: str) -> str:
    """Самостоятельный SVG-документ иконки."""
    return ('<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" '
            f'viewBox="0 0 48 48">{icon_inner(device_type)}</svg>')


# ─── Карточка узла ───────────────────────────────────────────────────────────

def card_lines(dev: "Device") -> tuple[str, str, str]:
    """(заголовок, строка IP, строка «производитель · ОС»)."""
    from oui_db import short_vendor
    title = dev.display_name()
    if dev.is_virtual:
        count = ""
        return (title, DEVICE_TYPE_LABELS["segment"], count)
    ip_line = dev.ip
    extra = len(dev.interfaces) - 1
    if extra > 0:
        ip_line += f"  +{extra} IP"
    if title == dev.ip:
        title = DEVICE_TYPE_LABELS.get(dev.device_type, dev.device_type)
    parts = []
    vendor = short_vendor(dev.vendor)
    if vendor:
        parts.append(vendor)
    if dev.os_name:
        parts.append(dev.os_name)
    elif dev.model:
        parts.append(dev.model)
    if not parts:
        parts.append(DEVICE_TYPE_LABELS.get(dev.device_type, dev.device_type))
    return title, ip_line, " · ".join(parts)


def elide(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: max(1, limit - 1)] + "…"


@dataclass(frozen=True)
class Badge:
    text: str
    bg: str
    fg: str = "#ffffff"
    tooltip: str = ""


# Порт → (текст, цвет, типы устройств, для которых бейдж имеет смысл)
_PORT_BADGES: list[tuple[int, str, str, set[str] | None]] = [
    (3389, "RDP", "#c0392b", {"windows_endpoint", "windows_server", "server",
                              "endpoint", "unknown"}),
    (22, "SSH", "#27ae60", {"linux_server", "linux_endpoint", "router",
                            "switch", "firewall", "server", "nas", "unknown",
                            "access_point", "bridge"}),
    (23, "TEL", "#d35400", {"router", "switch", "bridge", "firewall",
                            "access_point", "unknown"}),
    (5900, "VNC", "#8e44ad", None),
    (5985, "WRM", "#16a085", None),
    (161, "SNMP", "#2c3e50", None),
]


def card_badges(dev: "Device") -> tuple[list[Badge], list[Badge]]:
    """(бейджи слева сверху — роль, справа сверху — доступные службы)."""
    left: list[Badge] = []
    if dev.is_scanner:
        left.append(Badge("ВЫ", "#2c3e50", tooltip="Компьютер сканирования"))
    if dev.is_gateway:
        left.append(Badge("GW", "#c0392b", tooltip="Шлюз подсети"))
    if dev.is_multihomed:
        left.append(Badge("★", "#f39c12", tooltip="Несколько интерфейсов"))
    right: list[Badge] = []
    ports = set(dev.open_ports)
    for port, text, color, types in _PORT_BADGES:
        if port in ports and (types is None or dev.device_type in types):
            right.append(Badge(text, color, tooltip=f"Открыт порт {port}"))
    return left[:3], right[:4]


def device_tooltip(dev: "Device") -> str:
    """Многострочное описание устройства (подсказки, draw.io, HTML)."""
    lines = [dev.display_name(),
             f"Тип: {DEVICE_TYPE_LABELS.get(dev.device_type, dev.device_type)}"
             + (f" ({dev.confidence}%)" if dev.confidence else "")]
    if not dev.is_virtual:
        lines.append(f"IP: {', '.join(dev.all_ips())}")
    for label, value in (("MAC", dev.mac), ("Производитель", dev.vendor),
                         ("ОС", dev.os_name), ("Модель", dev.model),
                         ("Подсеть", dev.subnet),
                         ("Хопов от сканера", dev.hops),
                         ("Расположение", dev.location),
                         ("Заметки", dev.notes)):
        if value not in (None, ""):
            lines.append(f"{label}: {value}")
    if dev.open_ports:
        lines.append("Порты: " + ", ".join(str(p) for p in dev.open_ports))
    return "\n".join(lines)


# ─── Связи ───────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class LinkStyle:
    color: str
    width: float
    dash: tuple[float, ...] = ()


LINK_STYLES: dict[str, LinkStyle] = {
    "manual":       LinkStyle("#27ae60", 2.2),
    "lldp":         LinkStyle("#1f618d", 2.6),
    "cdp":          LinkStyle("#1f618d", 2.6),
    "fdb":          LinkStyle("#2e86c1", 2.2),
    "snmp-arp":     LinkStyle("#566573", 1.8),
    "ARP":          LinkStyle("#7f8c8d", 1.6),
    "traceroute":   LinkStyle("#8e44ad", 2.0, (7, 4)),
    "inter-subnet": LinkStyle("#e74c3c", 2.0, (8, 3, 2, 3)),
    "inferred":     LinkStyle("#99a3a4", 1.5),
    "heuristic":    LinkStyle("#b2babb", 1.3, (2, 3)),
    "":             LinkStyle("#7f8c8d", 1.6),
}


def link_style(kind: str) -> LinkStyle:
    return LINK_STYLES.get(kind, LINK_STYLES[""])


def link_label(kind: str) -> str:
    return LINK_LABELS.get(kind, kind or LINK_LABELS[""])


# ─── Зоны подсетей ───────────────────────────────────────────────────────────

ZONE_PAD = 16.0
ZONE_PAD_LANE = 22.0     # дополнительный отступ слева под «гребёнку» связей
ZONE_LABEL_H = 22.0


def subnet_color(cidr: str) -> tuple[int, int, int]:
    """Стабильный пастельный цвет подсети (RGB)."""
    hue = int(hashlib.md5(cidr.encode()).hexdigest(), 16) % 360
    r, g, b = colorsys.hsv_to_rgb(hue / 360, 0.35, 0.92)
    return int(r * 255), int(g * 255), int(b * 255)


def zone_members(topology: "NetworkTopology") -> dict[str, list[str]]:
    """
    Подсеть → узлы для отрисовки зоны. Пограничные устройства (с несколькими
    интерфейсами или со связями в другие сети) в зону не входят — они
    соединяют зоны; иначе зона растянулась бы поверх соседней ветки.
    """
    groups: dict[str, list[str]] = {}
    for nid, dev in topology.devices.items():
        if dev.subnet:
            groups.setdefault(dev.subnet, []).append(nid)
    graph = topology.graph
    result = {}
    for cidr, nids in groups.items():
        def border(n: str) -> bool:
            dev = topology.devices[n]
            return dev.is_multihomed or any(
                topology.devices[nb].subnet != cidr
                for nb in graph.neighbors(n) if nb in topology.devices)
        plain = [n for n in nids if not border(n)]
        result[cidr] = plain or nids
    return dict(sorted(result.items(), key=lambda kv: ip_sort_key(
        kv[0].split("/")[0])))


def zone_rect(positions: list[tuple[float, float]]
              ) -> tuple[float, float, float, float]:
    """(x, y, w, h) прямоугольника зоны по центрам карточек."""
    xs = [p[0] for p in positions]
    ys = [p[1] for p in positions]
    # Слева отступ больше: там проходит вертикальная «гребёнка» связей
    # (layout: зазор между полосами дерева 64 px > 38 + 16)
    x0 = min(xs) - NODE_W / 2 - ZONE_PAD - ZONE_PAD_LANE
    y0 = min(ys) - NODE_H / 2 - ZONE_PAD - ZONE_LABEL_H
    x1 = max(xs) + NODE_W / 2 + ZONE_PAD
    y1 = max(ys) + NODE_H / 2 + ZONE_PAD
    return x0, y0, x1 - x0, y1 - y0
