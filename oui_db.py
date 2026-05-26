"""
oui_db.py — локальная OUI-база данных производителей по MAC-адресам.

Архитектура:
  OUIDatabase — синглтон-класс, загружает и кэширует базу в памяти.
  Поддерживает поиск по 3-байтовому OUI (MA-L) и 6-байтовому MA-S/MA-M.

Источники (в порядке приоритета):
  1. Wireshark manuf — https://gitlab.com/wireshark/wireshark/-/raw/master/manuf
     Формат: OUI\tShort\tFull description
     Обновляется еженедельно, ~6MB, содержит MA-L/MA-M/MA-S и специальные записи.
  2. IEEE OUI CSV — https://regauth.standards.ieee.org/standards-ra-web/pub/view.html
     Прямая ссылка: http://standards-oui.ieee.org/oui/oui.csv
     Официальный источник, ~3MB, только MA-L (24-bit OUI).

Хранение:
  Файл: data/oui_db.json  (рядом с oui_db.py)
  Формат: {"updated": "ISO-timestamp", "source": "...", "entries": {"AABBCC": "Vendor Name", ...}}
  Поиск: O(1) по dict-ключу (нормализованный OUI без разделителей, верхний регистр).

Обновление:
  - Авто: при запуске, если файл старше AUTO_UPDATE_DAYS дней
  - Вручную: update_database() / --update-oui в CLI / кнопка в GUI
  - При недоступности сети: продолжает работать с кэшем

Классификация по vendor:
  oui_to_device_type(vendor_string) возвращает (device_type, weight) или None.
  Используется в DeviceAnalyzer как дополнительный источник голосования.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import re
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("oui_db")

# ─── Конфигурация ────────────────────────────────────────────────────────────

# Директория для хранения базы (рядом со скриптом)
_BASE_DIR  = Path(__file__).parent / "data"
_DB_PATH   = _BASE_DIR / "oui_db.json"

# Авто-обновление если база старше N дней
AUTO_UPDATE_DAYS = 60

# Таймаут скачивания (сек)
DOWNLOAD_TIMEOUT = 30

# URLs источников
WIRESHARK_URL = (
    "https://gitlab.com/wireshark/wireshark/-/raw/master/manuf"
)
IEEE_OUI_URL = (
    "http://standards-oui.ieee.org/oui/oui.csv"
)

# ─── Паттерны классификации vendor → device_type ─────────────────────────────
# Формат: (список подстрок lower-case, device_type, weight)
# Чем специфичнее строка — тем выше вес.
VENDOR_TYPE_RULES: list[tuple[list[str], str, float]] = [
    # ── Сетевое оборудование (высокий приоритет) ──────────────────────────────
    ([
        "cisco", "cisco systems",
    ], "router", 5.0),
    ([
        "juniper networks", "juniper",
    ], "router", 5.0),
    ([
        "mikrotik", "routerboard",
    ], "router", 5.0),
    ([
        "ubiquiti", "ubnt",
    ], "router", 4.5),
    ([
        "aruba networks", "aruba",
    ], "switch", 4.5),
    ([
        "netgear",
    ], "switch", 4.0),
    ([
        "tp-link", "tp link",
    ], "switch", 4.0),
    ([
        "d-link", "d link",
    ], "switch", 4.0),
    ([
        "zyxel", "zyxel communications",
    ], "router", 4.5),
    ([
        "allied telesis", "allied telesyn",
    ], "switch", 4.0),
    ([
        "extreme networks",
    ], "switch", 4.5),
    ([
        "brocade communications",
    ], "switch", 4.5),
    ([
        "hewlett packard enterprise", "hpe",
    ], "switch", 4.0),
    # ── Межсетевые экраны ────────────────────────────────────────────────────
    ([
        "fortinet",
    ], "firewall", 5.5),
    ([
        "palo alto networks",
    ], "firewall", 5.5),
    ([
        "check point software", "checkpoint",
    ], "firewall", 5.5),
    ([
        "watchguard technologies", "watchguard",
    ], "firewall", 5.0),
    ([
        "sophos",
    ], "firewall", 5.0),
    ([
        "barracuda networks",
    ], "firewall", 4.5),
    # ── Серверное оборудование ────────────────────────────────────────────────
    ([
        "supermicro", "super micro",
    ], "linux_server", 4.5),
    ([
        "dell", "dell emc",
    ], "linux_server", 3.5),
    ([
        "ibm",
    ], "linux_server", 3.5),
    ([
        "oracle",
    ], "linux_server", 3.5),
    # ── Рабочие станции / ПК ─────────────────────────────────────────────────
    ([
        "apple", "apple, inc",
    ], "linux_endpoint", 4.0),
    ([
        "intel corporate", "intel",
    ], "windows_endpoint", 3.0),
    ([
        "lenovo", "ibm lenovo",
    ], "windows_endpoint", 3.5),
    ([
        "hewlett-packard", "hp inc",
    ], "windows_endpoint", 3.0),
    ([
        "hewlett packard",
    ], "switch", 3.5),  # HP сетевое оборудование / принтеры
    ([
        "samsung electronics",
    ], "windows_endpoint", 3.0),
    ([
        "asustek computer", "asus",
    ], "windows_endpoint", 3.5),
    ([
        "chongqing fugui electronics", "fugui",
    ], "windows_endpoint", 3.0),  # дешёвые китайские ПК/ТВ-боксы
    ([
        "shenzhen jmicron", "jmicron",
    ], "windows_endpoint", 3.0),
    ([
        "lg electronics",
    ], "windows_endpoint", 3.0),
    ([
        "huawei technologies",
    ], "windows_endpoint", 3.0),
    ([
        "xiaomi",
    ], "windows_endpoint", 3.0),
    # ── VoIP-телефоны и IP-АТС ──────────────────────────────────────────────────
    ([
        "grandstream networks", "grandstream",
    ], "voip_phone", 6.5),
    ([
        "yealink", "yealink network technology",
    ], "voip_phone", 6.5),
    ([
        "polycom", "poly",
    ], "voip_phone", 6.0),
    ([
        "snom technology", "snom",
    ], "voip_phone", 6.0),
    ([
        "fanvil technology", "fanvil",
    ], "voip_phone", 6.0),
    ([
        "htek technologies", "htek",
    ], "voip_phone", 6.0),
    ([
        "gigaset communications", "gigaset",
    ], "voip_phone", 6.0),
    ([
        "aastra technologies", "mitel networks",
    ], "voip_phone", 6.0),
    ([
        "avaya",
    ], "voip_phone", 5.5),

    # ── Принтеры / МФУ ────────────────────────────────────────────────────────
    ([
        "seiko epson", "epson",
    ], "printer", 5.5),
    ([
        "canon", "canon inc",
    ], "printer", 5.5),
    ([
        "ricoh", "ricoh company",
    ], "printer", 5.5),
    ([
        "kyocera", "kyocera document solutions", "kyocera display",
    ], "printer", 5.5),
    ([
        "xerox",
    ], "printer", 5.5),
    ([
        "lexmark",
    ], "printer", 5.5),
    ([
        "brother industries",
    ], "printer", 5.5),
    ([
        "konica minolta",
    ], "printer", 5.0),
    ([
        "sharp corporation",
    ], "printer", 4.5),
    ([
        "zhuhai pantum electronics", "pantum",
    ], "printer", 5.5),
    ([
        "zebra technologies", "bixolon",
    ], "printer", 5.0),
    # ── Виртуализация (скорее всего сервер) ─────────────────────────────────
    ([
        "vmware",
    ], "linux_server", 4.0),
    ([
        "oracle virtualbox", "cadmus computer systems",
        "pcs systemtechnik",  # 08:00:27 — VirtualBox default OUI
    ], "linux_server", 3.5),
    ([
        "proxmox",
    ], "linux_server", 4.5),
    # ── Сетевые накопители (NAS) ─────────────────────────────────────────────
    ([
        "synology incorporated", "synology", "qnap systems",
    ], "linux_server", 4.5),
    # ── IoT / embedded (не классифицируем точно → endpoint) ─────────────────
    ([
        "raspberry pi", "raspberrypi",
    ], "linux_endpoint", 4.0),
    ([
        "espressif", "espressif inc",
    ], "endpoint", 3.0),
    ([
        "arduino",
    ], "endpoint", 3.0),
]


def vendor_to_device_type(vendor: str) -> tuple[str, float] | None:
    """
    По строке производителя возвращает (device_type, weight) или None.
    Использует VENDOR_TYPE_RULES — список паттернов с весами.
    """
    if not vendor:
        return None
    vendor_lower = vendor.lower()
    best: tuple[str, float] | None = None
    for keywords, dtype, weight in VENDOR_TYPE_RULES:
        if any(kw in vendor_lower for kw in keywords):
            if best is None or weight > best[1]:
                best = (dtype, weight)
    return best


# ─── Класс базы данных OUI ───────────────────────────────────────────────────

class OUIDatabase:
    """
    Локальная OUI-база данных. Singleton-паттерн через _instance.

    Использование:
        db = OUIDatabase.get()
        vendor = db.lookup("AA:BB:CC:DD:EE:FF")    # → "Cisco Systems"
        vendor = db.lookup("AA:BB:CC")              # по OUI-prefix
    """

    _instance: Optional["OUIDatabase"] = None

    def __init__(self) -> None:
        # Словарь: нормализованный OUI (6 символов без разделителей) → vendor
        self._db: dict[str, str] = {}
        self._updated: datetime | None = None
        self._source: str = ""
        self._loaded = False

    @classmethod
    def get(cls) -> "OUIDatabase":
        """Возвращает единственный экземпляр (создаёт при первом вызове)."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ── Загрузка ─────────────────────────────────────────────────────────────

    def load(self, auto_update: bool = True) -> None:
        """
        Загружает базу из локального файла.
        Если файл не существует или устарел — скачивает обновление.

        auto_update: проверять возраст базы и обновлять если старше AUTO_UPDATE_DAYS.
        """
        _BASE_DIR.mkdir(parents=True, exist_ok=True)

        if _DB_PATH.exists():
            self._load_from_file()
            if auto_update and self._is_outdated():
                logger.info("OUI-база устарела (>%d дней), обновляем...",
                            AUTO_UPDATE_DAYS)
                self.update_database()
        else:
            logger.info("OUI-база не найдена, скачиваем...")
            self.update_database()

        self._loaded = True

    def _load_from_file(self) -> None:
        """Читает базу из JSON-файла."""
        try:
            with open(_DB_PATH, encoding="utf-8") as f:
                data = json.load(f)
            self._db     = data.get("entries", {})
            self._source = data.get("source", "")
            updated_str  = data.get("updated", "")
            if updated_str:
                self._updated = datetime.fromisoformat(updated_str)
            logger.info("OUI-база загружена: %d записей, источник: %s",
                        len(self._db), self._source)
        except Exception as exc:
            logger.warning("Ошибка чтения OUI-базы: %s", exc)
            self._db = {}

    def _is_outdated(self) -> bool:
        """True если база старше AUTO_UPDATE_DAYS дней."""
        if self._updated is None:
            return True
        age = (datetime.now(timezone.utc) - self._updated).days
        return age > AUTO_UPDATE_DAYS

    def _save_to_file(self) -> None:
        """Сохраняет текущую базу в JSON."""
        _BASE_DIR.mkdir(parents=True, exist_ok=True)
        data = {
            "updated": datetime.now(timezone.utc).isoformat(),
            "source":  self._source,
            "entries": self._db,
        }
        with open(_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        logger.info("OUI-база сохранена: %d записей → %s",
                    len(self._db), _DB_PATH)

    # ── Обновление базы ──────────────────────────────────────────────────────

    def update_database(self) -> bool:
        """
        Скачивает свежую базу из Wireshark (основной) или IEEE (резерв).
        Возвращает True при успехе.
        """
        # Попытка 1: Wireshark manuf
        logger.info("Скачиваем OUI из Wireshark manuf...")
        entries = self._fetch_wireshark()

        if not entries:
            # Попытка 2: IEEE OUI CSV
            logger.info("Wireshark недоступен, пробуем IEEE OUI CSV...")
            entries = self._fetch_ieee_csv()
            if entries:
                self._source = "IEEE"
        else:
            self._source = "Wireshark"

        if not entries:
            logger.error("Не удалось обновить OUI-базу (нет доступа к сети?)")
            return False

        self._db = entries
        self._save_to_file()
        logger.info("OUI-база обновлена: %d записей (источник: %s)",
                    len(self._db), self._source)
        return True

    def _fetch_wireshark(self) -> dict[str, str]:
        """
        Скачивает и парсит файл Wireshark manuf.

        Формат строк:
          # Комментарий
          AA:BB:CC          ShortName    Full Vendor Name
          AA:BB:CC:DD:EE    ShortName    MA-S запись (36-bit)
          AA:BB:CC:DD:EE:FF ShortName    MA-S запись (48-bit)

        Нас интересует OUI (первые 3 байта = 6 hex-символов).
        Для MA-S/MA-M записей тоже берём первые 3 байта как OUI,
        но с более низким приоритетом (запись MA-L перекрывает если есть).
        """
        entries: dict[str, str] = {}
        try:
            req  = urllib.request.Request(
                WIRESHARK_URL,
                headers={"User-Agent": "NetTopologyScanner/1.0"}
            )
            resp = urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT)
            raw  = resp.read().decode("utf-8", errors="replace")
        except Exception as exc:
            logger.warning("Wireshark download error: %s", exc)
            return {}

        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Разбиваем по пробелам/табуляции
            parts = re.split(r"\t+|\s{2,}", line, maxsplit=2)
            if len(parts) < 2:
                continue

            oui_raw  = parts[0].strip()
            # Полное название — третий столбец (если есть), иначе второй
            vendor   = parts[2].strip() if len(parts) >= 3 else parts[1].strip()

            # Нормализуем OUI: оставляем только первые 3 байта (6 hex-символов)
            oui_clean = re.sub(r"[:\-\./]", "", oui_raw).upper()
            if len(oui_clean) < 6:
                continue
            oui6 = oui_clean[:6]

            # Записи MA-L (ровно 6 hex) имеют приоритет над MA-S (>6 hex)
            if oui6 not in entries or len(oui_clean) == 6:
                entries[oui6] = vendor

        return entries

    def _fetch_ieee_csv(self) -> dict[str, str]:
        """
        Скачивает и парсит IEEE OUI CSV.

        Формат:
          Registry,Assignment,Organization Name,Organization Address
          MA-L,AABBCC,Cisco Systems Inc,...
        """
        entries: dict[str, str] = {}
        try:
            req  = urllib.request.Request(
                IEEE_OUI_URL,
                headers={"User-Agent": "NetTopologyScanner/1.0"}
            )
            resp = urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT)
            raw  = resp.read().decode("utf-8", errors="replace")
        except Exception as exc:
            logger.warning("IEEE OUI download error: %s", exc)
            return {}

        reader = csv.DictReader(io.StringIO(raw))
        for row in reader:
            oui    = row.get("Assignment", "").strip().upper()
            vendor = row.get("Organization Name", "").strip()
            if oui and vendor and len(oui) == 6:
                entries[oui] = vendor

        return entries

    # ── Поиск ────────────────────────────────────────────────────────────────

    def lookup(self, mac: str) -> str | None:
        """
        Поиск производителя по MAC-адресу или OUI-префиксу.

        Поддерживает форматы:
          "AA:BB:CC:DD:EE:FF" — полный MAC
          "AA:BB:CC"          — OUI-prefix
          "AABBCC"            — OUI без разделителей

        Возвращает название производителя или None если не найдено.
        Поиск идёт от более специфичного (6 байт = 12 hex) к менее (3 байта = 6 hex),
        чтобы корректно обрабатывать MA-S/MA-M записи.
        """
        if not self._loaded:
            self.load()

        if not mac:
            return None

        # Нормализуем: убираем разделители, верхний регистр
        clean = re.sub(r"[:\-\.]", "", mac).upper()
        if len(clean) < 6:
            return None

        # Пробуем от самого длинного префикса к самому короткому
        for length in [12, 10, 8, 6]:
            if len(clean) >= length:
                key = clean[:length]
                if key in self._db:
                    return self._db[key]

        return None

    def lookup_type(self, mac: str) -> tuple[str, float] | None:
        """
        Поиск производителя по MAC и классификация его по типу устройства.
        Возвращает (device_type, weight) или None.
        """
        vendor = self.lookup(mac)
        if not vendor:
            return None
        return vendor_to_device_type(vendor)

    # ── Статистика / утилиты ─────────────────────────────────────────────────

    @property
    def size(self) -> int:
        return len(self._db)

    @property
    def updated(self) -> datetime | None:
        return self._updated

    @property
    def source(self) -> str:
        return self._source

    @property
    def db_path(self) -> Path:
        return _DB_PATH

    def stats(self) -> str:
        """Строка со статистикой базы для отображения в GUI/CLI."""
        if not self._db:
            return "OUI-база не загружена"
        age = ""
        if self._updated:
            days = (datetime.now(timezone.utc) - self._updated).days
            age  = f", возраст: {days} дн."
        return (f"OUI-база: {self.size:,} записей | "
                f"источник: {self._source}{age} | "
                f"файл: {_DB_PATH}")


# ─── CLI-утилита обновления ───────────────────────────────────────────────────

def update_oui_cli() -> None:
    """
    Обновляет OUI-базу из командной строки.
    Вызывается через: python oui_db.py  или  net_topology.py --update-oui
    """
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")
    db = OUIDatabase.get()
    print("Обновление OUI-базы...")
    ok = db.update_database()
    if ok:
        print(db.stats())
    else:
        print("Ошибка: не удалось обновить базу. Проверьте интернет-соединение.")


if __name__ == "__main__":
    update_oui_cli()
