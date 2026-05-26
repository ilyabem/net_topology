# Сканер и редактор топологии сети

[![Tests](https://github.com/ilyabem/networkscanner/actions/workflows/tests.yml/badge.svg)](https://github.com/ilyabem/networkscanner/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)]()

Инструмент для обнаружения устройств в сети, классификации их типов и построения интерактивной топологической схемы с возможностью редактирования.

---

## Структура проекта

```
networkscanner/
├── net_topology.py     # Точка входа (CLI + запуск GUI)
├── scanner.py          # Сканирование сети (ARP + nmap)
├── analyzer.py         # Классификация устройств
├── model.py            # Модель данных (Device, NetworkTopology)
├── oui_db.py           # OUI-база производителей по MAC
├── gui.py              # Графический интерфейс (PyQt5)
├── test_topology.py    # Юнит-тесты (pytest)
├── requirements.txt    # Python-зависимости
├── README.md
└── data/               # Создаётся автоматически
    └── oui_db.json     # Локальный кэш OUI-базы (~4–6 MB)
```

---

## Установка

### Шаг 1 — Системные зависимости

#### Linux (Debian / Ubuntu)

```bash
# nmap — сканер портов (обязателен)
sudo apt install -y nmap

# Библиотеки Qt для работы GUI
sudo apt install -y \
    libxcb-cursor0 libxcb-xinerama0 libxcb-icccm4 libxcb-image0 \
    libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxcb-shape0 \
    libxcb-xfixes0 libxcb-xkb1 libxkbcommon-x11-0 libgl1 libglib2.0-0
```

#### macOS

```bash
brew install nmap
```

#### Windows

- Скачать и установить **nmap**: https://nmap.org/download.html
- Скачать и установить **Npcap**: https://npcap.com/ (отметить «WinPcap API-compatible mode»)

---

### Шаг 2 — Виртуальное окружение Python

```bash
# Создать окружение
python3 -m venv venv

# Активировать (Linux / macOS)
source venv/bin/activate

# Активировать (Windows)
venv\Scripts\activate.bat
```

> После активации в начале строки терминала появится `(venv)`.

---

### Шаг 3 — Python-зависимости

```bash
pip install -r requirements.txt
```

| Пакет | Назначение |
|---|---|
| `python-nmap` | Обёртка над системным nmap |
| `scapy` | ARP-сканирование L2 (требует root) |
| `networkx` | Граф топологии и layout |
| `numpy` | Spring layout для NetworkX |
| `PyQt5` | Графический интерфейс |
| `pysnmp==4.4.12` | SNMP-опрос устройств |
| `mac-vendor-lookup` | Fallback определение производителя |
| `pytest` | Запуск тестов |

---

### Полная установка одной командой (Linux/Ubuntu)

```bash
sudo apt install -y nmap \
    libxcb-cursor0 libxcb-xinerama0 libxcb-icccm4 libxcb-image0 \
    libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxcb-shape0 \
    libxcb-xfixes0 libxcb-xkb1 libxkbcommon-x11-0 libgl1 libglib2.0-0

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Использование

### Одна подсеть

```bash
venv/bin/python net_topology.py --subnet 192.168.1.0/24
```

### Несколько подсетей

```bash
# Через пробел
venv/bin/python net_topology.py --subnets 192.168.1.0/24 192.168.0.0/24

# Через запятую
venv/bin/python net_topology.py --subnets 192.168.1.0/24,192.168.0.0/24

# Параллельное сканирование
venv/bin/python net_topology.py --subnets 192.168.1.0/24 192.168.0.0/24 --parallel
```

### CLI-режим (без GUI)

```bash
venv/bin/python net_topology.py --subnet 192.168.1.0/24 --no-gui
```

### Загрузить сохранённую топологию

```bash
venv/bin/python net_topology.py --load topology.json
```

### Обновить OUI-базу производителей

```bash
venv/bin/python net_topology.py --update-oui
```

### Все аргументы

| Аргумент | Описание |
|---|---|
| `--subnet CIDR` | Одна подсеть |
| `--subnets CIDR [CIDR ...]` | Несколько подсетей (пробел или запятая) |
| `--community STRING` | SNMP community string (по умолчанию: `public`) |
| `--no-gui` | Только CLI-вывод |
| `--max-hosts N` | Ограничение хостов на подсеть (по умолчанию: 254) |
| `--load FILE` | Загрузить топологию из JSON |
| `--timeout SEC` | Таймаут ответа хоста (по умолчанию: 1.0) |
| `--parallel` | Параллельное сканирование подсетей |
| `--update-oui` | Обновить OUI-базу и выйти |

---

## Права доступа

| Платформа | Требование |
|---|---|
| **Linux/macOS** | `sudo` для ARP-сканирования (Scapy) |
| **Windows** | Запуск от Администратора + Npcap |

Если прав недостаточно — ARP-скан пропускается, ping-скан через nmap продолжает работать.

---

## Типы устройств

Программа определяет 13 типов устройств:

### Сетевое оборудование

| Тип | Цвет | Форма | Примеры |
|---|---|---|---|
| `router` | 🔴 красный | ромб | Cisco, MikroTik, Juniper, Huawei |
| `switch` | 🔵 синий | квадрат | HP ProCurve, Aruba, Netgear, D-Link |
| `firewall` | 🟠 оранжевый | треугольник | Fortinet, pfSense, Palo Alto, Check Point |
| `bridge` | 🟣 фиолетовый | шестиугольник | Linux bridge, сетевые мосты |

### Серверы

| Тип | Цвет | Форма | Примеры |
|---|---|---|---|
| `windows_server` | 🟦 бирюзовый | круг | Windows Server 2016/2019/2022, MSSQL (1433), WinRM (5985) |
| `linux_server` | 🟢 зелёный | круг | Ubuntu Server, CentOS, RHEL, Synology NAS, VMware ESXi |
| `server` | 🩵 светло-бирюзовый | круг | Сервер (ОС не определена) |

### Конечные точки

| Тип | Цвет | Форма | Примеры |
|---|---|---|---|
| `windows_endpoint` | ⬛ тёмно-синий | круг | Windows 10/11, ASUSTek, Samsung, RDP (3389) |
| `linux_endpoint` | ⚫ серый | круг | macOS, Ubuntu Desktop, Fedora, Raspberry Pi |
| `voip_phone` | 🩵 голубой | шестиугольник | Grandstream, Yealink, Polycom, Snom, Fanvil, Avaya |
| `printer` | 🟡 жёлтый | квадрат | Epson, Canon, Kyocera, Ricoh, HP LaserJet, Pantum |
| `endpoint` | ⬜ светло-серый | круг | Конечная точка (ОС не определена) |
| `unknown` | ⬜ очень светлый | круг | Тип не определён |

---

## Как определяется тип устройства

Используется **взвешенное голосование** — побеждает тип с наибольшей суммой весов:

| Источник | Макс. вес | Описание |
|---|---|---|
| Ключевые слова в sysDescr (SNMP) | 12 | «Windows Server 2019», «Cisco IOS», «Ubuntu Server» |
| Дефинитивные порты | 15 | Порт 9100 → printer, 5060 → voip_phone, 5985 → windows_server |
| OUI-база производителей | 6.5 | Grandstream → voip_phone, Fortinet → firewall, Kyocera → printer |
| Ключевые слова в hostname | 11 | «Grandstream», «pfSense», «MikroTik» |
| Обычные порты | до 8 | SSH, SMTP, PostgreSQL, RDP и др. |
| Gateway-эвристика | 4.5 | IP, оканчивающийся на `.1` или `.254` → router |
| TTL | 2 | 64 → Linux, 128 → Windows, 255 → сетевое оборудование |

### Примеры из реальной сети

| Устройство | MAC (OUI) | Порты | Результат |
|---|---|---|---|
| Grandstream GXP | Grandstream Networks | 80 | `voip_phone` ✓ |
| Kyocera принтер | KYOCERA Display Corp. | 80, 443, 445 | `printer` ✓ |
| Pantum принтер | Zhuhai Pantum Electronics | 80, 443 | `printer` ✓ |
| ASUSTek ПК | ASUSTek COMPUTER INC. | — | `windows_endpoint` ✓ |
| Synology NAS | Synology Incorporated | 80, 443, 445 | `linux_server` ✓ |
| HP свич | Hewlett Packard | 23, 80, 443 | `switch` ✓ |
| Huawei роутер | HUAWEI TECHNOLOGIES | 80, 8443 | `router` ✓ |

---

## OUI-база производителей

### Что это

При сканировании программа определяет производителя устройства по первым 3 байтам MAC-адреса (OUI) и использует это как один из признаков классификации.

### Хранение

База хранится локально в `data/oui_db.json` (~4–6 MB). При первом запуске скачивается автоматически.

### Источники (в порядке приоритета)

| Источник | URL | Размер | Обновление |
|---|---|---|---|
| Wireshark manuf | gitlab.com/wireshark | ~6 MB | еженедельно |
| IEEE OUI CSV | standards-oui.ieee.org | ~3 MB | ежемесячно |

### Обновление базы

```bash
# Из командной строки
venv/bin/python net_topology.py --update-oui

# Напрямую
venv/bin/python oui_db.py
```

Из GUI: **Правка → 🔄 Обновить OUI-базу...**

Автоматически: при запуске если база старше 60 дней.

### Поддерживаемые форматы MAC

| Формат | Пример |
|---|---|
| Linux | `aa:bb:cc:dd:ee:ff` |
| Windows | `AA-BB-CC-DD-EE-FF` |
| Cisco | `aabb.ccdd.eeff` |
| Без разделителей | `aabbccddeeff` |

---

## Работа с GUI

### Панель управления (вверху)

- **Подсети** — введите одну или несколько подсетей через запятую или пробел
- **Community** — SNMP community string
- **Параллельно** — сканировать подсети одновременно
- **▶ Сканировать** — запуск сканирования (в фоновом потоке, GUI не зависает)
- **🔽 Фильтр типов** — выпадающий список с чекбоксами для скрытия/показа типов

### Фильтрация типов устройств

При большом количестве устройств топология становится перегруженной. Используйте фильтр чтобы временно скрыть ненужные типы:

1. Нажмите **«🔽 Фильтр типов устройств»**
2. Снимите галочки с типов которые хотите скрыть
3. Узлы и все их связи скрываются мгновенно
4. Кнопки **«Все»** / **«Скрыть все»** для быстрого переключения

Группы фильтра:
- 🔴 Сетевое оборудование (router, switch, firewall, bridge)
- 🟢 Серверы (windows_server, linux_server, server)
- ⚫ Конечные точки (windows_endpoint, linux_endpoint, voip_phone, printer, endpoint)
- ⬜ Неизвестные (unknown)

### Управление узлами

- **Перетаскивание** — зажать левую кнопку мыши на узле
- **ПКМ на узле** — контекстное меню:
  - ✏️ Редактировать (IP, имя, MAC, тип, подсеть, заметки)
  - 🗑️ Удалить устройство
  - 🔗 Добавить связь
  - 🔀 Объединить с другим узлом (ручное объединение)
  - ✂️ Разделить интерфейс (только для мультиинтерфейсных)
- **ПКМ на связи** — удалить связь
- **ПКМ на пустом месте** — добавить новое устройство

### Масштаб

- **Колёсико мыши** — приближение/отдаление
- **Ctrl+F** — вписать всё в экран
- **Ctrl+0** — сбросить масштаб

---

## Мультиинтерфейсные устройства

При сканировании нескольких подсетей программа автоматически обнаруживает устройства с несколькими IP-адресами (роутеры, межсетевые экраны) по совпадению MAC-адреса и объединяет их в один узел.

**Визуально** — золотистая пунктирная рамка + символ ★ в подписи.

**Ручная корректировка:**
- ПКМ → **«Объединить с узлом»** — если автоматика не нашла совпадение
- ПКМ → **«Разделить интерфейс»** — если объединение ошибочно

**CLI-вывод** — мультиинтерфейсные помечены `*`:

```
*  192.168.0.1    AC:5E:14:9C:43:93  router    HUAWEI    gw.local
     ↳ 192.168.1.1 [192.168.1.0/24]
```

---

## Сохранение и экспорт

- **Ctrl+S** — сохранить топологию в JSON (все правки сохраняются)
- **Файл → Сохранить как** — выбрать путь
- **Файл → Экспорт GraphML** — для Gephi, yEd и других инструментов

JSON-файл сохраняет: все устройства с типами, позиции узлов, все связи, мультиинтерфейсные данные, OUI-vendor.

---

## Тесты

```bash
pip install pytest
pytest test_topology.py -v
```

Покрытие: normalize_mac, merge_by_mac, split_device, build_from_multi_subnet, classify_by_ports, classify_by_keywords, OUI-база, gateway-эвристика, VoIP-классификация, CLI-таблица — более 70 тестов.

---

## Устранение проблем

### pysnmp установлен, но SNMP не работает

**Симптом:** `pysnmp X.X: sync API недоступен. SNMP отключён.`

**Причина:** pysnmp 6.x/7.x (lextudio fork) перешёл на asyncio и несовместим со старым sync API.

**Решение:**
```bash
pip uninstall pysnmp -y
pip install "pysnmp==4.4.12"
```

**Альтернатива** — системный `snmpget` (программа обнаружит его автоматически):
```bash
sudo apt install snmp
```

### Устройство определено неверно

1. Правый клик на узле → **«✏️ Редактировать»**
2. Выберите правильный тип из списка
3. Сохраните топологию (**Ctrl+S**)

Изменение сохраняется в JSON и не пропадёт при следующем открытии файла (но будет перезаписано при новом сканировании).

### GUI не открывается (ошибка xcb)

```bash
sudo apt install -y \
    libxcb-cursor0 libxcb-xinerama0 libxcb-icccm4 libxcb-image0 \
    libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxcb-shape0 \
    libxcb-xfixes0 libxcb-xkb1 libxkbcommon-x11-0 libgl1
```

### Переменная DISPLAY не установлена (SSH без X11)

```bash
DISPLAY=:0 venv/bin/python net_topology.py --subnet 192.168.1.0/24
```

---

## Платформозависимые особенности

| Функция | Linux | Windows | macOS |
|---|---|---|---|
| ARP-сканирование (Scapy) | ✅ root | ✅ Admin + Npcap | ✅ root |
| nmap ping/port scan | ✅ | ✅ | ✅ |
| SNMP (pysnmp 4.4.12) | ✅ | ✅ | ✅ |
| GUI (PyQt5) | ✅ | ✅ | ✅ |
| OUI-база (авто-скачивание) | ✅ | ✅ | ✅ |
