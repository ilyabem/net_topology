# Сборка NetTopologyScanner.exe для Windows

## Требования

- Windows 10/11 (x64)
- Python 3.10, 3.11 или 3.12 — https://python.org/downloads
  - При установке отметить **«Add Python to PATH»**
- Npcap — https://npcap.com/ (нужен для ARP-сканирования Scapy)
  - При установке отметить **«WinPcap API-compatible mode»**
- nmap — https://nmap.org/download.html

---

## Способ 1 — Автоматическая сборка (рекомендуется)

### Через .bat (простой)

1. Скопируйте все файлы проекта в одну папку
2. Запустите **от имени Администратора**:
   ```
   build_windows.bat
   ```
3. Готово — результат в `dist\NetTopologyScanner\NetTopologyScanner.exe`

### Через PowerShell

```powershell
PowerShell -ExecutionPolicy Bypass -File build_windows.ps1
```

---

## Способ 2 — Ручная сборка

```bat
:: 1. Создать и активировать venv
python -m venv venv_build
venv_build\Scripts\activate.bat

:: 2. Установить зависимости
pip install pyinstaller
pip install -r requirements.txt

:: 3. Собрать exe
pyinstaller net_topology.spec --clean --noconfirm
```

---

## Структура результата

После сборки в папке `dist\NetTopologyScanner\` будет:

```
NetTopologyScanner\
├── NetTopologyScanner.exe   ← главный файл
├── PyQt5\                   ← библиотеки Qt
├── _internal\               ← все зависимости
└── ...
```

> **Важно:** распространять нужно всю папку `NetTopologyScanner\`, не только `.exe` — он зависит от файлов рядом.

---

## Использование EXE

```bat
:: GUI режим
NetTopologyScanner.exe --subnet 192.168.1.0/24

:: CLI без GUI + сохранение результата
NetTopologyScanner.exe --subnet 192.168.1.0/24 --no-gui --output result.json

:: Несколько подсетей
NetTopologyScanner.exe --subnets 192.168.1.0/24 10.0.0.0/24

:: Обновить OUI-базу
NetTopologyScanner.exe --update-oui
```

> **Права:** для ARP-сканирования запускайте от имени **Администратора**.
> Без прав ARP-скан будет пропущен, ping-скан через nmap продолжит работу.

---

## Возможные проблемы

### «DLL not found» или «Failed to execute script»
Убедитесь что распространяете всю папку `NetTopologyScanner\`, не только `.exe`.

### ARP-сканирование не работает
Установите Npcap: https://npcap.com/ с галочкой «WinPcap API-compatible mode».

### nmap не найден
Установите nmap: https://nmap.org/download.html и убедитесь что он добавлен в PATH.

### Антивирус блокирует exe
PyInstaller-бинарники иногда ложно срабатывают. Добавьте в исключения или соберите самостоятельно из исходников.

---

## Размер итогового файла

Ожидаемый размер папки: **~150–250 MB** (из-за PyQt5 + NumPy + Scapy).
После архивации в ZIP: ~80–120 MB.
