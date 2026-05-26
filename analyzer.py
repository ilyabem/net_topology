"""
analyzer.py — классификация устройств.

Источники голосования (взвешенная сумма):
  1. SNMP sysDescr / sysServices         — вес до 12
  2. Ключевые слова в hostname/sysDescr  — вес до 12
  3. Открытые порты                      — вес до 15
  4. OUI-база (oui_db.py)               — вес до 5.5
  5. Gateway-эвристика (.1/.254 в сети)  — вес 3.0
  6. TTL                                 — вес до 2
  7. Fallback VENDOR_WEIGHTS             — вес до 4

SNMP совместимость:
  Поддерживает pysnmp 4.x (classic hlapi) и pysnmp-lextudio 6/7.x.
  Определяется автоматически при импорте.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from model import Device

logger = logging.getLogger("analyzer")

# ─── pysnmp: автодетектор версии API ─────────────────────────────────────────
# Поддерживаем:
#   pysnmp 4.x           pip install "pysnmp==4.4.12"   (рекомендуется)
#   pysnmp-lextudio 6.x  sync API в v1arch.sync
#   netsnmp CLI          системная утилита snmpget

SNMP_AVAILABLE = False
_snmp_backend  = None

# Попытка 1: pysnmp 4.x classic hlapi
try:
    from pysnmp.hlapi import (  # type: ignore
        CommunityData, ContextData, ObjectIdentity,
        ObjectType, SnmpEngine, UdpTransportTarget, getCmd,
    )
    import inspect as _inspect
    if _inspect.isgeneratorfunction(getCmd):
        SNMP_AVAILABLE = True
        _snmp_backend  = "classic-4x"
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
        _snmp_backend  = "lextudio-sync"
    except Exception:
        pass

# Попытка 3: netsnmp CLI как fallback
if not SNMP_AVAILABLE:
    import shutil as _shutil
    if _shutil.which("snmpget"):
        SNMP_AVAILABLE = True
        _snmp_backend  = "netsnmp-cli"
    else:
        try:
            import pysnmp as _pysnmp  # type: ignore
            _ver = getattr(_pysnmp, "__version__", "?")
            logger.warning(
                "pysnmp %s: sync API недоступен. "
                "SNMP отключён. Решение: pip install 'pysnmp==4.4.12'", _ver
            )
        except ImportError:
            logger.warning(
                "pysnmp не установлен. "
                "Для SNMP: pip install 'pysnmp==4.4.12'"
            )

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

    (["pfsense","opnsense","fortigate","fortifw","checkpoint",
      "watchguard","sophos","junos srx","palo alto","cisco asa",
      "netscreen","asa firewall"],                            "firewall",         10),
    (["cisco ios","cisco nx-os","cisco ios-xe","ios software",
      "junos","routeros","mikrotik","edgeos","vyos",
      "openwrt","dd-wrt"],                                   "router",           10),
    (["catalyst","procurve","aruba","hp switch","netgear gs",
      "netgear fs","d-link switch","tp-link switch",
      "juniper ex","cisco sg","cisco sf",
      "коммутатор","switch software"],                       "switch",           10),
    (["bridge","бридж"],                                     "bridge",            8),
    (["windows server 2022","windows server 2019",
      "windows server 2016","windows server 2012",
      "windows server 2008","microsoft windows server"],     "windows_server",   12),
    (["ubuntu server","centos linux","red hat enterprise",
      "rhel","almalinux","rocky linux","oracle linux",
      "debian gnu/linux","debian 11","debian 12","debian 10",
      "suse linux enterprise","sles",
      "freebsd","proxmox","esxi","vmware esxi"],             "linux_server",     12),
    (["darwin","macos","mac os x","apple mac"],              "linux_endpoint",    9),
    (["ubuntu desktop","fedora","arch linux","manjaro",
      "pop!_os","elementary os","linux mint","kubuntu"],     "linux_endpoint",    9),
    (["windows 11","windows 10","windows 8","windows 7",
      "windows vista","windows xp",
      "microsoft windows 1","workstation"],                  "windows_endpoint",  9),
    (["grandstream","yealink","polycom","snom","fanvil",
      "htek","gigaset","voip phone","ip phone","sip phone",
      "cisco spa","cisco ip phone"],                          "voip_phone",       11),
    (["printer","принтер","laserjet","officejet","mfp",
      "мфу","ricoh","kyocera","xerox","canon printer",
      "epson","brother mfc","hp color",
      "pantum","kyocera display"],                            "printer",          11),
    (["linux","unix","nginx","apache","postfix",
      "openssh","snmpd"],                                    "linux_server",      5),
    (["windows","microsoft","msrpc","netbios"],              "windows_endpoint",  4),
]

# ─── Порты ───────────────────────────────────────────────────────────────────
PORT_WEIGHTS: dict[int, list[tuple[str, float]]] = {
    23:   [("router",4),("switch",3)],
    161:  [("router",5),("switch",5)],
    179:  [("router",6)],
    520:  [("router",4)],
    21:   [("linux_server",3),("server",2)],
    22:   [("linux_server",3),("router",2)],
    25:   [("linux_server",5),("windows_server",4)],
    53:   [("linux_server",3),("router",2)],
    67:   [("router",3),("linux_server",2)],
    80:   [("linux_server",2),("windows_server",2),("printer",2)],
    110:  [("linux_server",4),("windows_server",4)],
    143:  [("linux_server",4),("windows_server",4)],
    389:  [("windows_server",5),("linux_server",4)],
    443:  [("linux_server",2),("windows_server",2)],
    445:  [("windows_server",2.5),("windows_endpoint",2),("printer",1.5)],  # SMB: сервер, ПК или сетевой принтер
    636:  [("windows_server",4),("linux_server",4)],
    993:  [("linux_server",4),("windows_server",3)],
    995:  [("linux_server",4),("windows_server",3)],
    1433: [("windows_server",6)],
    1521: [("linux_server",5),("windows_server",4)],
    3306: [("linux_server",6),("windows_server",3)],
    5432: [("linux_server",6)],
    5985: [("windows_server",5),("windows_endpoint",3)],
    5986: [("windows_server",5)],
    6379: [("linux_server",5)],
    8080: [("linux_server",2),("windows_server",2)],
    8443: [("linux_server",2),("windows_server",2)],
    27017:[("linux_server",5)],
    3389: [("windows_endpoint",5),("windows_server",4)],
    # VoIP
    5060: [("voip_phone", 8), ("router", 2)],   # SIP
    5061: [("voip_phone", 7)],                   # SIP TLS
    1720: [("voip_phone", 6)],                   # H.323
    9100: [("printer",8)],
    515:  [("printer",7)],
    631:  [("printer",6)],
}

DEFINITIVE_PORTS: dict[int, str] = {
    5060: "voip_phone",
    9100: "printer",
    515:  "printer",
    1433: "windows_server",
    5985: "windows_server",
}

TTL_HINTS: list[tuple[range, str, float]] = [
    (range(63, 66),   "linux_server",     1.5),
    (range(127, 130), "windows_endpoint", 1.5),
    (range(250, 256), "router",           2.0),
]

VENDOR_WEIGHTS_FALLBACK: list[tuple[list[str], str, float]] = [
    (["cisco","juniper","mikrotik","ubiquiti","aruba",
      "zyxel","d-link","tp-link","netgear","extreme"],       "router",           4),
    (["fortinet","watchguard","palo alto","checkpoint"],      "firewall",         4),
    (["supermicro","dell","ibm","oracle"],                    "linux_server",     2),
    (["apple"],                                              "linux_endpoint",    3),
    (["samsung","lg","huawei","xiaomi"],                     "windows_endpoint",  2),
    (["seiko epson","canon","ricoh","kyocera",
      "xerox","lexmark","brother"],                          "printer",          5),
    (["vmware","virtualbox","proxmox"],                      "linux_server",     3),
]


class DeviceAnalyzer:
    """Классифицирует Device по всем доступным признакам."""

    def __init__(self, snmp_community: str = "public",
                 snmp_timeout: float = 1.0,
                 use_oui_db: bool = True) -> None:
        self.snmp_community = snmp_community
        self.snmp_timeout   = snmp_timeout
        self.use_oui_db     = use_oui_db and OUI_DB_AVAILABLE

        if self.use_oui_db:
            try:
                self._oui = OUIDatabase.get()
                if not self._oui._loaded:
                    self._oui.load(auto_update=True)
                logger.info("OUI-база готова: %s", self._oui.stats())
            except Exception as exc:
                logger.warning("Не удалось загрузить OUI-базу: %s", exc)
                self.use_oui_db = False

    def enrich(self, device: "Device") -> None:
        """Запускает все источники классификации, выбирает победителя."""
        scores: dict[str, float] = {}

        def vote(dtype: str, w: float) -> None:
            scores[dtype] = scores.get(dtype, 0) + w

        # 1. SNMP
        if SNMP_AVAILABLE and 161 in device.open_ports:
            r = self._query_snmp(device)
            if r:
                dtype, weight, sys_name = r
                vote(dtype, weight)
                if sys_name and not device.hostname:
                    device.hostname = sys_name

        # 2. Ключевые слова в hostname
        if device.hostname:
            self._keywords_vote(device.hostname, scores)

        # 3. Порты
        self._ports_vote(device.open_ports, scores)

        # 4. OUI-база
        if self.use_oui_db and device.mac:
            r = self._oui_vote(device)
            if r:
                vote(*r)

        # 5. Gateway-эвристика: .1 или .254 в подсети → скорее всего router
        self._gateway_vote(device, scores)

        # 6. TTL
        if device.ttl is not None:
            for rng, dtype, w in TTL_HINTS:
                if device.ttl in rng:
                    vote(dtype, w)

        # 7. Fallback vendor string
        if device.vendor and not (self.use_oui_db and device.mac):
            vendor_lower = device.vendor.lower()
            for keywords, dtype, w in VENDOR_WEIGHTS_FALLBACK:
                if any(kw in vendor_lower for kw in keywords):
                    vote(dtype, w)
                    break

        # 8. LAA-эвристика: Locally Administered Address (рандомный MAC)
        #    Android 10+, iOS 14+, Windows 11 используют рандомизацию MAC.
        #    Bit 1 первого октета = 1 означает LAA.
        #    Если нет других признаков — помечаем как мобильное endpoint.
        if device.mac:
            self._laa_vote(device.mac, scores)

        # 8b. LAA + TTL=128 → скорее Windows 11 Wi-Fi, не мобильное
        if scores.get("mobile_device", 0) > 0 and device.ttl in range(127, 130):
            mob = scores.pop("mobile_device")
            scores["windows_endpoint"] = scores.get("windows_endpoint", 0) + mob + 2.0

        # 9. Hostname-эвристика: определяем ОС по имени хоста
        if device.hostname:
            self._hostname_os_vote(device.hostname, scores)

        # 10. Собственная машина сканера: нет MAC (не виден через ARP)
        #     но есть hostname — это сам сканирующий хост
        if not device.mac and device.hostname and not scores:
            self._hostname_os_vote(device.hostname, scores)

        if scores:
            device.device_type = max(scores, key=lambda k: scores[k])
        else:
            device.device_type = "unknown"

        logger.info("%-18s → %-18s  %s",
                    device.ip, device.device_type,
                    {k: round(v,1) for k, v in
                     sorted(scores.items(), key=lambda x:-x[1])[:4]})

    # ── Gateway-эвристика ────────────────────────────────────────────────────

    @staticmethod
    def _gateway_vote(device: "Device", scores: dict[str, float]) -> None:
        """
        Если IP-адрес устройства оканчивается на .1 или .254 — это вероятный
        шлюз (router/firewall). Добавляем умеренный вес чтобы не перекрыть
        другие более точные признаки, но помочь при неопределённости.

        Примеры: 192.168.1.1, 10.0.0.1, 172.16.0.254 → +3.0 к router
        """
        try:
            addr = ipaddress.ip_address(device.ip)
            last_octet = int(str(addr).split(".")[-1])
            if last_octet in (1, 254):
                scores["router"] = scores.get("router", 0) + 4.5
                logger.debug("%s: gateway-эвристика (+4.5 router)", device.ip)
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

        device.snmp_info = result
        sys_descr    = result.get(OID_SYS_DESCR, "").lower()
        sys_services = result.get(OID_SYS_SERVICES, "0")
        sys_name     = result.get(OID_SYS_NAME, "")

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
        engine    = SnmpEngine()
        community = CommunityData(self.snmp_community, mpModel=1)
        transport = UdpTransportTarget(
            (ip, 161), timeout=self.snmp_timeout, retries=1)
        context   = ContextData()
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
                     "-t", str(int(self.snmp_timeout)), ip, oid],
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
    def _keywords_vote(text: str, scores: dict[str, float]) -> None:
        text_lower = text.lower()
        for keywords, dtype, w in KEYWORD_PATTERNS:
            if any(kw in text_lower for kw in keywords):
                scores[dtype] = scores.get(dtype, 0) + w

    # ── LAA-эвристика ────────────────────────────────────────────────────────

    @staticmethod
    def _laa_vote(mac: str, scores: dict[str, float]) -> None:
        """
        Locally Administered Address (LAA) — рандомизированный MAC.
        Bit 1 первого октета = 1 → устройство скрывает реальный OUI.
        Характерно для: Android 10+, iOS 14+, Windows 11 Wi-Fi.

        По одному MAC невозможно отличить Android от iOS от Windows 11 —
        все они рандомизируют адрес одинаково. Поэтому всегда ставим
        mobile_device. Единственное исключение — TTL=128 (Windows) —
        обрабатывается в блоке 8b выше.
        """
        try:
            first_byte = int(mac.split(":")[0], 16)
            if first_byte & 0x02:   # LAA bit
                scores["mobile_device"]    = scores.get("mobile_device",    0) + 4.0
                scores["windows_endpoint"] = scores.get("windows_endpoint", 0) + 1.0
        except (ValueError, IndexError):
            pass

    # ── Hostname-эвристика ────────────────────────────────────────────────────

    # Паттерны hostname → (device_type, weight)
    HOSTNAME_OS_PATTERNS: list[tuple[list[str], str, float]] = [
        # Linux серверы и рабочие станции
        (["ubuntu", "debian", "mint", "fedora", "arch",
          "manjaro", "centos", "rhel", "rocky", "alma",
          "kali", "parrot", "linux"],                    "linux_endpoint",   5.0),
        # macOS
        (["macbook", "imac", "mac-mini", "mac-pro",
          "mbp", "mba"],                                 "linux_endpoint",   5.0),
        # Windows рабочие станции (включая брендовые имена ПК)
        (["desktop", "workstation", "pc-", "-pc",
          "win10", "win11", "msft",
          "msi-", "lenovo-", "asus-", "hp-", "dell-",
          "acer-", "toshiba-", "samsung-"],              "windows_endpoint", 4.0),
        # Windows серверы
        (["server", "srv", "dc-", "-dc", "ad-",
          "exchange", "fileserver", "fs-"],               "windows_server",   4.0),
        # Сетевое оборудование
        (["router", "gw", "gateway", "fw", "firewall",
          "switch", "sw-", "-sw"],                       "router",           4.0),
        # Принтеры
        (["printer", "print", "mfp", "copier",
          "kyocera", "epson", "canon", "ricoh"],         "printer",          5.0),
        # VoIP
        (["phone", "voip", "sip", "grandstream",
          "yealink", "polycom"],                         "voip_phone",       5.0),
        # NAS / серверы
        (["nas", "synology", "qnap", "storage",
          "backup", "media"],                            "linux_server",     4.0),
        # Мобильные устройства по hostname → всегда mobile_device
        (["iphone", "ipad", "ipod",
          "android", "pixel", "galaxy", "xiaomi",
          "redmi", "poco", "oneplus", "realme", "oppo",
          "phone", "mobile", "tablet",
          "смартфон", "планшет"],                       "mobile_device",    5.0),
    ]

    @classmethod
    def _hostname_os_vote(cls, hostname: str, scores: dict[str, float]) -> None:
        """
        Определяет ОС/тип по имени хоста.
        Особые случаи:
          - hostname содержит «ubuntu»/«debian» → linux_endpoint
          - hostname содержит «server»/«srv» → windows_server
          - hostname самого сканирующего ПК → определяем его ОС
        """
        h = hostname.lower()
        for keywords, dtype, w in cls.HOSTNAME_OS_PATTERNS:
            if any(kw in h for kw in keywords):
                scores[dtype] = scores.get(dtype, 0) + w
                logger.debug("hostname %r → %s (+%.1f)", hostname, dtype, w)
                break  # берём первое совпадение (наиболее специфичное)

    # ── Порты ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _ports_vote(ports: list[int], scores: dict[str, float]) -> None:
        port_set = set(ports)
        for port, dtype in DEFINITIVE_PORTS.items():
            if port in port_set:
                scores[dtype] = scores.get(dtype, 0) + 15
                return
        for port in port_set:
            for dtype, w in PORT_WEIGHTS.get(port, []):
                scores[dtype] = scores.get(dtype, 0) + w


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
