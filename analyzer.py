"""
analyzer.py — классификация устройств и определение ОС.

Работает только с данными, которые уже собрал сканер (MAC, TTL, имя хоста,
открытые порты, SNMP) — дополнительных запросов к сети не выполняет, кроме
SNMP-опроса устройств с открытым портом 161.

Источники голосования за тип устройства (взвешенная сумма):
  1. SNMP sysDescr / sysServices         — вес до 12
  2. Ключевые слова в hostname/sysDescr  — вес до 12
  3. Открытые порты                      — вес до 15
  4. OUI-база (oui_db.py)                — вес до 6.5
  5. Gateway-эвристика (.1/.254 в сети)  — вес 4.5
  6. TTL                                 — вес до 2
  7. Fallback VENDOR_WEIGHTS             — вес до 5
  8. Определённое семейство ОС           — вес до 3

Результат: device_type, confidence (%), evidence (пояснения), os_family,
os_name, hops (оценка по TTL).

SNMP совместимость:
  Поддерживает pysnmp 4.x (classic hlapi) и pysnmp-lextudio 6/7.x,
  а также системную утилиту snmpget. Определяется автоматически при импорте.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import TYPE_CHECKING

from model import is_laa_mac

if TYPE_CHECKING:
    from model import Device

logger = logging.getLogger("analyzer")

# ─── pysnmp: автодетектор версии API ─────────────────────────────────────────
# Поддерживаем:
#   pysnmp 4.x           pip install "pysnmp==4.4.12"   (Python ≤ 3.11)
#   pysnmp-lextudio 6.x  sync API в v1arch.sync
#   netsnmp CLI          системная утилита snmpget

SNMP_AVAILABLE = False
_snmp_backend = None

# Попытка 1: pysnmp 4.x classic hlapi
try:
    from pysnmp.hlapi import (  # type: ignore
        CommunityData, ContextData, ObjectIdentity,
        ObjectType, SnmpEngine, UdpTransportTarget, getCmd,
    )
    import inspect as _inspect
    if _inspect.isgeneratorfunction(getCmd):
        SNMP_AVAILABLE = True
        _snmp_backend = "classic-4x"
except Exception:
    pass

# Попытка 2: pysnmp-lextudio sync API (6.x)
if not SNMP_AVAILABLE:
    try:
        from pysnmp.hlapi.v1arch.sync import (  # type: ignore
            CommunityData, ContextData, ObjectIdentity,
            ObjectType, SnmpEngine, UdpTransportTarget, getCmd,
        )
        SNMP_AVAILABLE = True
        _snmp_backend = "lextudio-sync"
    except Exception:
        pass

# Попытка 3: netsnmp CLI как fallback
if not SNMP_AVAILABLE:
    import shutil as _shutil
    if _shutil.which("snmpget"):
        SNMP_AVAILABLE = True
        _snmp_backend = "netsnmp-cli"
    else:
        logger.debug("SNMP-библиотека не найдена: SNMP-опрос отключён")

# ─── OUI-база ────────────────────────────────────────────────────────────────
try:
    from oui_db import OUIDatabase, vendor_to_device_type
    OUI_DB_AVAILABLE = True
except ImportError:
    OUI_DB_AVAILABLE = False
    logger.warning("oui_db.py не найден.")

OID_SYS_DESCR    = "1.3.6.1.2.1.1.1.0"
OID_SYS_SERVICES = "1.3.6.1.2.1.1.7.0"
OID_SYS_NAME     = "1.3.6.1.2.1.1.5.0"

# ─── Ключевые слова ──────────────────────────────────────────────────────────
KEYWORD_PATTERNS: list[tuple[list[str], str, float]] = [
    # Мобильные устройства — первыми, чтобы "iphone" не попал в voip_phone
    (["iphone", "ipad", "ipod",
      "galaxy", "pixel", "xiaomi", "redmi",
      "oneplus", "realme", "oppo", "poco"],                  "mobile_device",   12),

    (["pfsense", "opnsense", "fortigate", "fortifw", "checkpoint",
      "watchguard", "sophos", "junos srx", "palo alto", "cisco asa",
      "netscreen", "asa firewall", "usergate", "ideco"],     "firewall",         10),
    (["cisco ios", "cisco nx-os", "cisco ios-xe", "ios software",
      "junos", "routeros", "mikrotik", "edgeos", "vyos",
      "openwrt", "dd-wrt", "keenetic", "huawei versatile routing"],
                                                             "router",           10),
    (["catalyst", "procurve", "aruba", "hp switch", "netgear gs",
      "netgear fs", "d-link switch", "tp-link switch",
      "juniper ex", "cisco sg", "cisco sf", "comware",
      "коммутатор", "switch software"],                      "switch",           10),
    (["unifi ap", "access point", "wireless access", "точка доступа"],
                                                             "access_point",     10),
    (["bridge", "бридж"],                                    "bridge",            8),
    (["windows server 2025", "windows server 2022", "windows server 2019",
      "windows server 2016", "windows server 2012",
      "windows server 2008", "microsoft windows server"],    "windows_server",   12),
    (["synology", "diskstation", "qnap", "truenas", "freenas"],
                                                             "nas",              12),
    (["hikvision", "dahua", "ip camera", "network camera", "nvr"],
                                                             "ip_camera",        11),
    (["ubuntu server", "centos linux", "red hat enterprise",
      "rhel", "almalinux", "rocky linux", "oracle linux",
      "debian gnu/linux", "debian 11", "debian 12", "debian 10",
      "suse linux enterprise", "sles", "astra linux", "red os",
      "freebsd", "proxmox", "esxi", "vmware esxi"],          "linux_server",     12),
    (["darwin", "macos", "mac os x", "apple mac"],           "linux_endpoint",    9),
    (["ubuntu desktop", "fedora", "arch linux", "manjaro",
      "pop!_os", "elementary os", "linux mint", "kubuntu"],  "linux_endpoint",    9),
    (["windows 11", "windows 10", "windows 8", "windows 7",
      "windows vista", "windows xp",
      "microsoft windows 1", "workstation"],                 "windows_endpoint",  9),
    (["grandstream", "yealink", "polycom", "snom", "fanvil",
      "htek", "gigaset", "voip phone", "ip phone", "sip phone",
      "cisco spa", "cisco ip phone"],                         "voip_phone",       11),
    (["printer", "принтер", "laserjet", "officejet", "mfp",
      "мфу", "ricoh", "kyocera", "xerox", "canon printer",
      "epson", "brother mfc", "hp color", "jetdirect",
      "pantum", "kyocera display"],                           "printer",          11),
    (["linux", "unix", "nginx", "apache", "postfix",
      "openssh", "snmpd"],                                   "linux_server",      5),
    (["windows", "microsoft", "msrpc", "netbios"],           "windows_endpoint",  4),
]

# ─── Порты ───────────────────────────────────────────────────────────────────
PORT_WEIGHTS: dict[int, list[tuple[str, float]]] = {
    23:   [("router", 4), ("switch", 3)],
    161:  [("router", 5), ("switch", 5)],
    179:  [("router", 6)],
    520:  [("router", 4)],
    8291: [("router", 9)],                       # MikroTik Winbox
    8728: [("router", 8)],                       # MikroTik API
    21:   [("linux_server", 3), ("server", 2)],
    22:   [("linux_server", 3), ("router", 2)],
    25:   [("linux_server", 5), ("windows_server", 4)],
    53:   [("linux_server", 3), ("router", 2)],
    67:   [("router", 3), ("linux_server", 2)],
    80:   [("linux_server", 2), ("windows_server", 2), ("printer", 2)],
    88:   [("windows_server", 8)],               # Kerberos → контроллер домена
    110:  [("linux_server", 4), ("windows_server", 4)],
    135:  [("windows_endpoint", 3), ("windows_server", 2)],
    139:  [("windows_endpoint", 2), ("windows_server", 1.5)],
    143:  [("linux_server", 4), ("windows_server", 4)],
    389:  [("windows_server", 5), ("linux_server", 4)],
    443:  [("linux_server", 2), ("windows_server", 2)],
    445:  [("windows_server", 2.5), ("windows_endpoint", 2), ("printer", 1.5)],
    548:  [("nas", 4), ("linux_endpoint", 3)],   # AFP
    554:  [("ip_camera", 7)],                    # RTSP
    636:  [("windows_server", 4), ("linux_server", 4)],
    993:  [("linux_server", 4), ("windows_server", 3)],
    995:  [("linux_server", 4), ("windows_server", 3)],
    1433: [("windows_server", 6)],
    1521: [("linux_server", 5), ("windows_server", 4)],
    1883: [("iot", 6)],                          # MQTT
    2049: [("nas", 4), ("linux_server", 4)],     # NFS
    3260: [("nas", 6)],                          # iSCSI
    3306: [("linux_server", 6), ("windows_server", 3)],
    5000: [("nas", 3)],
    5001: [("nas", 4)],
    5432: [("linux_server", 6)],
    5900: [("linux_endpoint", 2), ("windows_endpoint", 2)],
    5985: [("windows_server", 5), ("windows_endpoint", 3)],
    5986: [("windows_server", 5)],
    6379: [("linux_server", 5)],
    7547: [("router", 6)],                       # TR-069 (CPE)
    8000: [("ip_camera", 3)],
    8006: [("linux_server", 7)],                 # Proxmox VE
    8080: [("linux_server", 2), ("windows_server", 2)],
    8443: [("linux_server", 2), ("windows_server", 2)],
    27017: [("linux_server", 5)],
    37777: [("ip_camera", 8)],                   # Dahua
    62078: [("mobile_device", 9)],               # Apple iOS lockdownd
    3389: [("windows_endpoint", 5), ("windows_server", 4)],
    # VoIP
    5060: [("voip_phone", 8), ("router", 2)],    # SIP
    5061: [("voip_phone", 7)],                   # SIP TLS
    1720: [("voip_phone", 6)],                   # H.323
    9100: [("printer", 8)],
    515:  [("printer", 7)],
    631:  [("printer", 6)],
}

DEFINITIVE_PORTS: dict[int, str] = {
    5060: "voip_phone",
    9100: "printer",
    515:  "printer",
    1433: "windows_server",
    5985: "windows_server",
}

PORT_NAMES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    88: "Kerberos", 110: "POP3", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    515: "LPD", 548: "AFP", 554: "RTSP", 631: "IPP", 636: "LDAPS",
    1433: "MS SQL", 1521: "Oracle", 1720: "H.323", 1883: "MQTT",
    2049: "NFS", 3260: "iSCSI", 3306: "MySQL", 3389: "RDP", 5000: "HTTP-alt",
    5001: "HTTPS-alt", 5060: "SIP", 5061: "SIP-TLS", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM", 5986: "WinRM-TLS", 6379: "Redis",
    7547: "TR-069", 8000: "HTTP-alt", 8006: "Proxmox", 8080: "HTTP-proxy",
    8291: "Winbox", 8443: "HTTPS-alt", 8728: "MikroTik API", 9100: "JetDirect",
    27017: "MongoDB", 37777: "Dahua", 62078: "iOS sync",
}

TTL_HINTS: list[tuple[range, str, float]] = [
    (range(63, 66),   "linux_server",     1.5),
    (range(127, 130), "windows_endpoint", 1.5),
    (range(250, 256), "router",           2.0),
]

VENDOR_WEIGHTS_FALLBACK: list[tuple[list[str], str, float]] = [
    (["cisco", "juniper", "mikrotik", "ubiquiti", "aruba",
      "zyxel", "d-link", "tp-link", "netgear", "extreme"],    "router",           4),
    (["fortinet", "watchguard", "palo alto", "checkpoint"],   "firewall",         4),
    (["supermicro", "dell", "ibm", "oracle"],                 "linux_server",     2),
    (["apple"],                                               "linux_endpoint",   3),
    (["samsung", "lg", "huawei", "xiaomi"],                   "windows_endpoint", 2),
    (["seiko epson", "canon", "ricoh", "kyocera",
      "xerox", "lexmark", "brother"],                         "printer",          5),
    (["hikvision", "dahua", "axis"],                          "ip_camera",        5),
    (["synology", "qnap"],                                    "nas",              5),
    (["vmware", "virtualbox", "proxmox"],                     "linux_server",     3),
]

# ─── Определение ОС ──────────────────────────────────────────────────────────
# (паттерн regex, семейство, название, вес). Применяется к sysDescr, имени
# хоста и производителю. Первое совпадение в каждом тексте.
OS_PATTERNS: list[tuple[str, str, str, float]] = [
    (r"windows server 2025",              "windows", "Windows Server 2025", 10),
    (r"windows server 2022",              "windows", "Windows Server 2022", 10),
    (r"windows server 2019",              "windows", "Windows Server 2019", 10),
    (r"windows server 2016",              "windows", "Windows Server 2016", 10),
    (r"windows server 2012",              "windows", "Windows Server 2012", 10),
    (r"windows server",                   "windows", "Windows Server", 9),
    (r"windows 11",                       "windows", "Windows 11", 10),
    (r"windows 10",                       "windows", "Windows 10", 10),
    (r"windows 7",                        "windows", "Windows 7", 10),
    (r"software: windows",                "windows", "Windows", 9),
    (r"cisco ios[- ]xe",                  "network", "Cisco IOS XE", 10),
    (r"cisco nx-os",                      "network", "Cisco NX-OS", 10),
    (r"cisco adaptive security",          "network", "Cisco ASA", 10),
    (r"cisco ios",                        "network", "Cisco IOS", 10),
    (r"routeros|mikrotik",                "network", "MikroTik RouterOS", 10),
    (r"junos",                            "network", "Juniper Junos", 10),
    (r"fortios|fortigate",                "network", "FortiOS", 10),
    (r"pan-os|palo alto",                 "network", "PAN-OS", 10),
    (r"huawei versatile routing|\bvrp\b", "network", "Huawei VRP", 10),
    (r"comware",                          "network", "H3C Comware", 10),
    (r"arubaos|procurve",                 "network", "ArubaOS", 9),
    (r"edgeos|edgeswitch",                "network", "Ubiquiti EdgeOS", 9),
    (r"keenetic",                         "network", "Keenetic OS", 9),
    (r"openwrt|dd-wrt",                   "embedded", "OpenWrt", 9),
    (r"pfsense",                          "bsd", "pfSense", 10),
    (r"opnsense",                         "bsd", "OPNsense", 10),
    (r"truenas|freenas",                  "bsd", "TrueNAS", 10),
    (r"freebsd",                          "bsd", "FreeBSD", 9),
    (r"vmware esxi|\besxi\b",             "linux", "VMware ESXi", 10),
    (r"proxmox",                          "linux", "Proxmox VE", 10),
    (r"synology|diskstation|\bdsm\b",     "linux", "Synology DSM", 10),
    (r"\bqnap\b|\bqts\b",                 "linux", "QNAP QTS", 10),
    (r"astra linux|\bastra\b",            "linux", "Astra Linux", 9),
    (r"red os|redos",                     "linux", "РЕД ОС", 9),
    (r"ubuntu",                           "linux", "Ubuntu Linux", 9),
    (r"debian",                           "linux", "Debian Linux", 9),
    (r"centos",                           "linux", "CentOS Linux", 9),
    (r"red hat|\brhel\b",                 "linux", "Red Hat Enterprise Linux", 9),
    (r"rocky",                            "linux", "Rocky Linux", 8),
    (r"almalinux",                        "linux", "AlmaLinux", 9),
    (r"fedora",                           "linux", "Fedora Linux", 8),
    (r"raspberry|raspbian",               "linux", "Raspberry Pi OS", 8),
    (r"darwin|macos|mac os x|macbook|imac|mac-mini|mac-pro",
                                          "macos", "macOS", 9),
    (r"iphone|ipad|ipod",                 "ios", "iOS / iPadOS", 9),
    (r"android|galaxy|redmi|\bpoco\b|oneplus|realme|\boppo\b|pixel",
                                          "android", "Android", 8),
    (r"jetdirect|laserjet|officejet",     "embedded", "HP JetDirect", 9),
    (r"\blinux\b",                        "linux", "Linux", 6),
    (r"desktop-[a-z0-9]{5,}",             "windows", "Windows", 7),
    (r"^win-[a-z0-9]{6,}",                "windows", "Windows Server", 7),
]
_OS_RE = [(re.compile(p, re.IGNORECASE), fam, name, w)
          for p, fam, name, w in OS_PATTERNS]

OS_FAMILY_LABELS: dict[str, str] = {
    "windows": "Windows", "linux": "Linux", "macos": "macOS", "ios": "iOS",
    "android": "Android", "bsd": "BSD", "network": "Сетевая ОС",
    "embedded": "Встроенная ОС",
}

# Семейство ОС → голоса за тип устройства
OS_TYPE_VOTES: dict[str, list[tuple[str, float]]] = {
    "windows":  [("windows_endpoint", 2.5)],
    "linux":    [("linux_server", 1.5), ("linux_endpoint", 1.0)],
    "macos":    [("linux_endpoint", 3.0)],
    "ios":      [("mobile_device", 3.0)],
    "android":  [("mobile_device", 3.0)],
    "bsd":      [("linux_server", 1.5)],
    "network":  [("router", 2.0)],
}

# Порты серверных служб: их наличие отличает сервер от рабочей станции
SERVER_PORTS = {21, 25, 53, 88, 110, 143, 389, 636, 993, 995, 1433, 1521,
                3306, 5432, 5985, 5986, 6379, 8006, 27017}


def estimate_hops(ttl: int | None) -> int | None:
    """Оценка числа L3-хопов: исходный TTL (32/64/128/255) минус полученный."""
    if ttl is None or ttl <= 0:
        return None
    for initial in (32, 64, 128, 255):
        if ttl <= initial:
            return initial - ttl
    return None


def detect_os(device: "Device") -> tuple[str, str, float, list[str]]:
    """
    Определяет ОС по уже собранным данным.
    Возвращает (семейство, название, вес, пояснения); семейство '' — неизвестно.
    """
    votes: dict[str, float] = {}
    names: dict[str, tuple[str, float]] = {}
    evidence: list[str] = []

    def add(fam: str, name: str, w: float, why: str) -> None:
        votes[fam] = votes.get(fam, 0) + w
        if fam not in names or w > names[fam][1]:
            names[fam] = (name, w)
        evidence.append(f"{why} → {name} (+{w:g})")

    texts = [
        ("SNMP sysDescr", (device.snmp_info or {}).get(OID_SYS_DESCR, ""), 1.0),
        ("Имя хоста", device.hostname or "", 0.7),
        ("Имя NetBIOS", device.netbios_name or "", 0.7),
        ("Производитель", device.vendor or "", 0.5),
    ]
    for source, text, factor in texts:
        if not text:
            continue
        for rx, fam, name, w in _OS_RE:
            if rx.search(text):
                add(fam, name, w * factor, f"{source} «{_clip(text)}»")
                break

    ports = set(device.open_ports)
    if ports & {135, 445, 3389, 5985}:
        found = sorted(ports & {135, 445, 3389, 5985})
        add("windows", "Windows", 3.0,
            "Порты " + ", ".join(PORT_NAMES.get(p, str(p)) for p in found))
    if device.netbios_name and "windows" not in votes:
        add("windows", "Windows", 2.0, "Отвечает по NetBIOS")
    if 62078 in ports:
        add("ios", "iOS / iPadOS", 6.0, "Порт 62078 (iOS sync)")
    if 8291 in ports or 8728 in ports:
        add("network", "MikroTik RouterOS", 6.0, "Порт Winbox/API MikroTik")

    vendor = (device.vendor or "").lower()
    if "apple" in vendor and not ports & {62078}:
        add("macos", "macOS", 1.5, "Производитель Apple")

    if device.ttl:
        hops = estimate_hops(device.ttl) or 0
        initial = device.ttl + hops
        if initial == 128:
            add("windows", "Windows", 2.0, f"TTL {device.ttl} (исходный 128)")
        elif initial == 64:
            # TTL 64 у Linux, macOS, iOS, Android — отдаём голос лидеру
            fam = next((f for f in ("linux", "macos", "ios", "android", "bsd")
                        if f in votes), "linux")
            add(fam, names.get(fam, ("Linux / Unix", 0))[0], 1.5,
                f"TTL {device.ttl} (исходный 64)")
        elif initial == 255:
            add("network", "Сетевая ОС", 1.5, f"TTL {device.ttl} (исходный 255)")

    if not votes:
        return "", "", 0.0, []
    fam = max(votes, key=lambda f: votes[f])
    name = names[fam][0]
    if name == "Windows" and (ports & SERVER_PORTS & {88, 389, 636, 1433,
                                                      5985, 5986}):
        name = "Windows Server"
    return fam, name, votes[fam], evidence


def _clip(text: str, n: int = 40) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1] + "…"


class DeviceAnalyzer:
    """Классифицирует Device по всем доступным признакам."""

    def __init__(self, snmp_community: str = "public",
                 snmp_timeout: float = 1.0,
                 use_oui_db: bool = True) -> None:
        self.snmp_community = snmp_community
        self.snmp_timeout = snmp_timeout
        self.use_oui_db = use_oui_db and OUI_DB_AVAILABLE

        if self.use_oui_db:
            try:
                self._oui = OUIDatabase.get()
                self._oui.ensure_loaded(auto_update=True)
                logger.info("OUI-база готова: %s", self._oui.stats())
            except Exception as exc:
                logger.warning("Не удалось загрузить OUI-базу: %s", exc)
                self.use_oui_db = False

    def enrich(self, device: "Device") -> None:
        """Запускает все источники классификации, выбирает победителя."""
        scores: dict[str, float] = {}
        evidence: list[str] = []

        def vote(dtype: str, w: float, why: str = "") -> None:
            scores[dtype] = scores.get(dtype, 0) + w
            if why:
                evidence.append(f"{why} → {dtype} (+{w:g})")

        # 1. SNMP
        if SNMP_AVAILABLE and 161 in device.open_ports:
            r = self._query_snmp(device)
            if r:
                dtype, weight, sys_name = r
                vote(dtype, weight, "SNMP")
                if sys_name and not device.hostname:
                    device.hostname = sys_name
        sys_descr = (device.snmp_info or {}).get(OID_SYS_DESCR, "")
        if sys_descr and not any(e.startswith("SNMP") for e in evidence):
            kw = self._match_keywords(sys_descr)
            if kw:
                vote(kw, 10.0, f"SNMP sysDescr «{_clip(sys_descr)}»")

        # 2. Ключевые слова в hostname
        if device.hostname:
            self._keywords_vote(device.hostname, scores, evidence)

        # 3. Порты
        self._ports_vote(device.open_ports, scores, evidence)

        # 4. OUI-база
        oui_vendor_found = False
        if self.use_oui_db and device.mac:
            r = self._oui_vote(device)
            try:
                oui_vendor_found = bool(self._oui.lookup(device.mac))
            except Exception:  # noqa: BLE001
                oui_vendor_found = False
            if r:
                vote(r[0], r[1], f"Производитель «{_clip(device.vendor or '')}»")

        # 5. Gateway-эвристика: .1 или .254 в подсети → скорее всего router
        self._gateway_vote(device, scores, evidence)
        if device.is_gateway:
            vote("router", 6.0, "Шлюз по умолчанию для подсети")

        # 6. TTL
        if device.ttl is not None:
            for rng, dtype, w in TTL_HINTS:
                if device.ttl in rng:
                    vote(dtype, w, f"TTL {device.ttl}")
            if device.hops is None:
                device.hops = estimate_hops(device.ttl)

        # 7. Fallback vendor string
        if device.vendor and not (self.use_oui_db and device.mac):
            vendor_lower = device.vendor.lower()
            for keywords, dtype, w in VENDOR_WEIGHTS_FALLBACK:
                if any(kw in vendor_lower for kw in keywords):
                    vote(dtype, w, f"Производитель «{_clip(device.vendor)}»")
                    break

        # 8. LAA-эвристика: Locally Administered Address (рандомный MAC).
        #    Android 10+, iOS 14+, Windows 11 используют рандомизацию MAC.
        #    Если производитель по OUI найден — адрес не случайный.
        if device.mac and not oui_vendor_found:
            self._laa_vote(device.mac, scores, evidence)

        # 8b. LAA + TTL=128 → скорее Windows 11 Wi-Fi, не мобильное
        if scores.get("mobile_device", 0) > 0 and device.ttl in range(127, 130) \
                and 62078 not in device.open_ports:
            mob = scores.pop("mobile_device")
            vote("windows_endpoint", mob + 2.0, "Случайный MAC + TTL 128")

        # 9. Hostname-эвристика: определяем ОС по имени хоста
        if device.hostname:
            self._hostname_os_vote(device.hostname, scores, evidence)

        # 10. Семейство ОС
        fam, os_name, os_weight, os_evidence = detect_os(device)
        if fam:
            device.os_family = fam
            if not device.os_name:
                device.os_name = os_name
            strength = min(1.0, os_weight / 8)
            server_like = bool(set(device.open_ports) & SERVER_PORTS)
            for dtype, w in OS_TYPE_VOTES.get(fam, []):
                if fam in ("windows", "linux", "bsd") and server_like:
                    dtype = "windows_server" if fam == "windows" else \
                        "linux_server"
                vote(dtype, round(w * strength, 2), f"ОС {os_name}")

        if scores:
            device.device_type = max(scores, key=lambda k: scores[k])
            top = scores[device.device_type]
            share = top / sum(scores.values())
            device.confidence = max(5, min(99, round(
                100 * share * (0.5 + 0.5 * min(1.0, top / 12)))))
        else:
            device.device_type = "unknown"
            device.confidence = 0

        device.evidence = evidence + [f"ОС: {e}" for e in os_evidence]
        logger.info("%-18s → %-18s %3d%%  %s",
                    device.ip, device.device_type, device.confidence,
                    {k: round(v, 1) for k, v in
                     sorted(scores.items(), key=lambda x: -x[1])[:4]})

    # ── Gateway-эвристика ────────────────────────────────────────────────────

    @staticmethod
    def _gateway_vote(device: "Device", scores: dict[str, float],
                      evidence: list[str] | None = None) -> None:
        """
        Если IP-адрес устройства оканчивается на .1 или .254 — это вероятный
        шлюз (router/firewall). Добавляем умеренный вес чтобы не перекрыть
        другие более точные признаки, но помочь при неопределённости.
        """
        try:
            addr = ipaddress.ip_address(device.ip)
            if addr.version != 4:
                return
            last_octet = int(str(addr).split(".")[-1])
            if last_octet in (1, 254):
                scores["router"] = scores.get("router", 0) + 4.5
                if evidence is not None:
                    evidence.append(f"Адрес .{last_octet} — типичный для шлюза"
                                    " → router (+4.5)")
        except ValueError:
            pass

    # ── OUI-база ─────────────────────────────────────────────────────────────

    def _oui_vote(self, device: "Device") -> tuple[str, float] | None:
        try:
            vendor = self._oui.lookup(device.mac)
            if vendor:
                device.vendor = vendor
                result = vendor_to_device_type(vendor)
                if result:
                    logger.debug("OUI %s → %s → %s (%.1f)",
                                 device.mac, vendor, result[0], result[1])
                return result
        except Exception as exc:
            logger.debug("OUI lookup error: %s", exc)
        return None

    # ── SNMP ─────────────────────────────────────────────────────────────────

    def _query_snmp(self, device: "Device") -> tuple[str, float, str] | None:
        try:
            result = self._snmp_get(
                device.ip, [OID_SYS_DESCR, OID_SYS_SERVICES, OID_SYS_NAME])
        except Exception as exc:
            logger.debug("SNMP %s: %s", device.ip, exc)
            return None
        if not result:
            return None

        device.snmp_info = result
        if result.get(OID_SYS_NAME):
            device.snmp_info["sysName"] = result[OID_SYS_NAME]
        sys_descr = result.get(OID_SYS_DESCR, "").lower()
        sys_services = result.get(OID_SYS_SERVICES, "0")
        sys_name = result.get(OID_SYS_NAME, "")

        kw = self._match_keywords(sys_descr)
        if kw:
            return kw, 10.0, sys_name
        dtype = parse_snmp_services(sys_services)
        if dtype:
            return dtype, 7.0, sys_name
        return None

    def _snmp_get(self, ip: str, oids: list[str]) -> dict[str, str]:
        """
        SNMP GET запрос. Поддерживает:
          - pysnmp 4.x / lextudio sync API (приоритет)
          - netsnmp CLI (snmpget) как fallback
        """
        if _snmp_backend == "netsnmp-cli":
            return self._snmp_get_cli(ip, oids)
        return self._snmp_get_pysnmp(ip, oids)

    def _snmp_get_pysnmp(self, ip: str, oids: list[str]) -> dict[str, str]:
        """Использует pysnmp library (4.x или lextudio sync)."""
        result: dict[str, str] = {}
        engine = SnmpEngine()
        community = CommunityData(self.snmp_community, mpModel=1)
        transport = UdpTransportTarget(
            (ip, 161), timeout=self.snmp_timeout, retries=1)
        context = ContextData()
        for oid in oids:
            ei, es, _, vbs = next(getCmd(
                engine, community, transport, context,
                ObjectType(ObjectIdentity(oid))))
            if not ei and not es:
                for vb in vbs:
                    result[oid] = str(vb[1])
        return result

    def _snmp_get_cli(self, ip: str, oids: list[str]) -> dict[str, str]:
        """Fallback: вызывает системный snmpget через subprocess."""
        import subprocess
        result: dict[str, str] = {}
        for oid in oids:
            try:
                out = subprocess.check_output(
                    ["snmpget", "-v2c", "-c", self.snmp_community,
                     "-t", str(max(1, int(self.snmp_timeout))), ip, oid],
                    stderr=subprocess.DEVNULL,
                    timeout=self.snmp_timeout + 1,
                )
                # Парсим: OID = TYPE: value
                line = out.decode(errors="replace").strip()
                if "=" in line:
                    value = line.split("=", 1)[1].strip()
                    # Убираем тип (STRING: "...", INTEGER: ...)
                    if ":" in value:
                        value = value.split(":", 1)[1].strip().strip('"')
                    result[oid] = value
            except Exception:
                pass
        return result

    # ── Ключевые слова ────────────────────────────────────────────────────────

    @staticmethod
    def _match_keywords(text: str) -> str | None:
        text_lower = text.lower()
        best: tuple[str, float] | None = None
        for keywords, dtype, w in KEYWORD_PATTERNS:
            if any(kw in text_lower for kw in keywords):
                if best is None or w > best[1]:
                    best = (dtype, w)
        return best[0] if best else None

    @staticmethod
    def _keywords_vote(text: str, scores: dict[str, float],
                       evidence: list[str] | None = None) -> None:
        text_lower = text.lower()
        for keywords, dtype, w in KEYWORD_PATTERNS:
            hit = next((kw for kw in keywords if kw in text_lower), None)
            if hit:
                scores[dtype] = scores.get(dtype, 0) + w
                if evidence is not None:
                    evidence.append(f"«{hit}» в имени хоста → {dtype} (+{w:g})")

    # ── LAA-эвристика ────────────────────────────────────────────────────────

    @staticmethod
    def _laa_vote(mac: str, scores: dict[str, float],
                  evidence: list[str] | None = None) -> None:
        """
        Locally Administered Address (LAA) — рандомизированный MAC.
        Bit 1 первого октета = 1 → устройство скрывает реальный OUI.
        Характерно для: Android 10+, iOS 14+, Windows 11 Wi-Fi.

        По одному MAC невозможно отличить Android от iOS от Windows 11 —
        все они рандомизируют адрес одинаково. Поэтому ставим
        mobile_device. Исключение — TTL=128 (Windows), блок 8b.
        """
        if is_laa_mac(mac):
            scores["mobile_device"] = scores.get("mobile_device", 0) + 4.0
            scores["windows_endpoint"] = scores.get("windows_endpoint", 0) + 1.0
            if evidence is not None:
                evidence.append("Случайный (LAA) MAC → mobile_device (+4)")

    # ── Hostname-эвристика ────────────────────────────────────────────────────

    # Паттерны hostname → (device_type, weight). Порядок важен: берётся первое
    # совпадение. Короткие ключи (≤ 4 символов) сравниваются как целые слова,
    # ключи с дефисом и длинные — как подстроки.
    HOSTNAME_OS_PATTERNS: list[tuple[list[str], str, float]] = [
        # Мобильные устройства — раньше VoIP, чтобы «iphone» не стал телефоном
        (["iphone", "ipad", "ipod",
          "android", "pixel", "galaxy", "xiaomi",
          "redmi", "poco", "oneplus", "realme", "oppo",
          "mobile", "tablet",
          "смартфон", "планшет"],                       "mobile_device",    5.0),
        # Linux серверы и рабочие станции
        (["ubuntu", "debian", "mint", "fedora", "arch",
          "manjaro", "centos", "rhel", "rocky", "alma",
          "kali", "parrot", "linux", "astra"],          "linux_endpoint",   5.0),
        # macOS
        (["macbook", "imac", "mac-mini", "mac-pro",
          "mbp", "mba"],                                "linux_endpoint",   5.0),
        # Windows серверы (WIN-XXXXXXX — имя Windows Server по умолчанию)
        (["server", "srv", "dc-", "-dc", "ad-", "win-",
          "exchange", "fileserver", "fs-"],              "windows_server",   4.0),
        # Windows рабочие станции (включая брендовые имена ПК)
        (["desktop", "workstation", "pc-", "-pc", "pc",
          "win10", "win11", "msft", "laptop", "notebook",
          "msi-", "lenovo-", "asus-", "hp-", "dell-",
          "acer-", "toshiba-", "samsung-"],             "windows_endpoint", 4.0),
        # Межсетевые экраны
        (["fw", "firewall", "fortigate", "pfsense", "utm",
          "ngfw", "usergate"],                          "firewall",         4.5),
        # Точки доступа
        (["ap", "wap", "wifi", "wi-fi", "unifi", "access-point"],
                                                        "access_point",     4.0),
        # Коммутаторы
        (["switch", "sw", "sw-", "-sw", "catalyst", "core", "access"],
                                                        "switch",           4.0),
        # Маршрутизаторы
        (["router", "gw", "gateway", "rtr", "mikrotik", "keenetic",
          "edge"],                                      "router",           4.0),
        # Принтеры
        (["printer", "print", "mfp", "copier",
          "kyocera", "epson", "canon", "ricoh", "laserjet"],
                                                        "printer",          5.0),
        # VoIP
        (["phone", "voip", "sip", "grandstream",
          "yealink", "polycom"],                        "voip_phone",       5.0),
        # Камеры
        (["cam", "camera", "ipcam", "nvr", "dvr", "hikvision", "dahua"],
                                                        "ip_camera",        5.0),
        # NAS
        (["nas", "synology", "qnap", "storage", "diskstation"],
                                                        "nas",              4.5),
        # Серверы
        (["backup", "media", "proxmox", "esxi", "pve", "hv", "hyperv"],
                                                        "linux_server",     4.0),
    ]

    @staticmethod
    def _hostname_matches(hostname: str, keyword: str) -> bool:
        if "-" in keyword or len(keyword) >= 5:
            return keyword in hostname
        tokens = re.split(r"[^a-zа-яё]+", hostname)
        return keyword in tokens

    @classmethod
    def _hostname_os_vote(cls, hostname: str, scores: dict[str, float],
                          evidence: list[str] | None = None) -> None:
        """Определяет тип по имени хоста (первое совпадение)."""
        h = hostname.lower().split(".")[0]
        for keywords, dtype, w in cls.HOSTNAME_OS_PATTERNS:
            hit = next((kw for kw in keywords
                        if cls._hostname_matches(h, kw)), None)
            if hit:
                scores[dtype] = scores.get(dtype, 0) + w
                if evidence is not None:
                    evidence.append(f"Имя хоста «{hostname}» ({hit}) → "
                                    f"{dtype} (+{w:g})")
                logger.debug("hostname %r → %s (+%.1f)", hostname, dtype, w)
                break

    # ── Порты ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _ports_vote(ports: list[int], scores: dict[str, float],
                    evidence: list[str] | None = None) -> None:
        port_set = set(ports)
        for port, dtype in DEFINITIVE_PORTS.items():
            if port in port_set:
                scores[dtype] = scores.get(dtype, 0) + 15
                if evidence is not None:
                    evidence.append(f"Порт {port} ({PORT_NAMES.get(port, '?')})"
                                    f" однозначно → {dtype} (+15)")
                return
        for port in sorted(port_set):
            for dtype, w in PORT_WEIGHTS.get(port, []):
                scores[dtype] = scores.get(dtype, 0) + w
            if evidence is not None and port in PORT_WEIGHTS:
                best = max(PORT_WEIGHTS[port], key=lambda x: x[1])
                evidence.append(f"Порт {port} ({PORT_NAMES.get(port, '?')})"
                                f" → {best[0]} (+{best[1]:g})")


# ─── Публичные функции для тестов ─────────────────────────────────────────────

def classify_by_ports(open_ports: list[int]) -> str | None:
    scores: dict[str, float] = {}
    DeviceAnalyzer._ports_vote(open_ports, scores)
    return max(scores, key=lambda k: scores[k]) if scores else None


def classify_by_keywords(text: str) -> str | None:
    return DeviceAnalyzer._match_keywords(text)


def parse_snmp_services(sys_services_value: str) -> str | None:
    """
    RFC 1213 sysServices:
      bit1 (2)  → switch
      bit2 (4)  → router
      bit6 (64) → linux_server
    """
    try:
        svc = int(sys_services_value)
    except (ValueError, TypeError):
        return None
    if svc & 4 and not (svc & 64):
        return "router"
    if svc & 2 and not (svc & 4) and not (svc & 64):
        return "switch"
    if svc & 64:
        return "linux_server"
    return None
