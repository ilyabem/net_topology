# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec-файл для сборки net_topology.exe
#
# Запуск сборки:
#   pyinstaller net_topology.spec
#
# Результат: dist/NetTopologyScanner/NetTopologyScanner.exe

import sys
from pathlib import Path

block_cipher = None

# Собираем все нужные данные и скрытые импорты
a = Analysis(
    ['net_topology.py'],
    pathex=[str(Path('.').resolve())],
    binaries=[],
    datas=[
        # Включаем data/ если OUI-база уже скачана
        # ('data/oui_db.json', 'data'),
    ],
    hiddenimports=[
        # PyQt5
        'PyQt5',
        'PyQt5.QtCore',
        'PyQt5.QtGui',
        'PyQt5.QtWidgets',
        'PyQt5.sip',
        # NetworkX
        'networkx',
        'networkx.algorithms',
        'networkx.drawing',
        'PyQt5.QtSvg',
        'PyQt5.QtPrintSupport',
        # Модули проекта (часть импортируется лениво)
        'model',
        'layout',
        'visual',
        'exporters',
        'analyzer',
        'scanner',
        'oui_db',
        'gui',
        # Scapy (опционально — большой, но нужен для ARP)
        'scapy',
        'scapy.all',
        'scapy.layers.l2',
        'scapy.layers.inet',
        # python-nmap
        'nmap',
        # pysnmp
        # pysnmp — только если установлен (Python <= 3.11)
        # mac-vendor-lookup
        'mac_vendor_lookup',
        # Экспорт в Excel
        'openpyxl',
        # Стандартная библиотека
        'ipaddress',
        'json',
        'logging',
        'socket',
        'subprocess',
        'threading',
        'concurrent.futures',
        'urllib.request',
        'csv',
        'io',
        're',
        'math',
        'uuid',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'PIL',
        'IPython',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='NetTopologyScanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,            # сжатие UPX (уменьшает размер exe)
    console=True,        # консоль видна — нужна для логов и CLI-режима
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,           # можно указать 'icon.ico'
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='NetTopologyScanner',
)
