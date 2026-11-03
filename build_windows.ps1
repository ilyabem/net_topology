# build_windows.ps1 — PowerShell версия сборщика (альтернатива .bat)
# Запуск: PowerShell -ExecutionPolicy Bypass -File build_windows.ps1

Write-Host "=== Сборка NetTopologyScanner для Windows ===" -ForegroundColor Cyan

# Проверяем Python
try {
    $pyver = python --version 2>&1
    Write-Host "[OK] $pyver" -ForegroundColor Green
} catch {
    Write-Host "[ОШИБКА] Python не найден. Установите Python 3.10+ с https://python.org" -ForegroundColor Red
    exit 1
}

# Виртуальное окружение
Write-Host "[1/5] Создание виртуального окружения..." -ForegroundColor Yellow
python -m venv venv_build
& .\venv_build\Scripts\Activate.ps1

# Зависимости
Write-Host "[2/5] Установка зависимостей..." -ForegroundColor Yellow
pip install --upgrade pip -q
pip install pyinstaller -q
pip install -r requirements.txt -q

# Проверка
Write-Host "[3/5] Проверка зависимостей..." -ForegroundColor Yellow
$check = python -c "import PyQt5.QtSvg, PyQt5.QtPrintSupport, networkx, nmap; print('OK')" 2>&1
if ($check -ne "OK") {
    Write-Host "[ОШИБКА] Зависимости не установлены: $check" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Все зависимости установлены" -ForegroundColor Green

# Сборка
Write-Host "[4/5] Сборка exe..." -ForegroundColor Yellow
pyinstaller net_topology.spec --clean --noconfirm

if (-not (Test-Path "dist\NetTopologyScanner\NetTopologyScanner.exe")) {
    Write-Host "[ОШИБКА] Сборка не удалась" -ForegroundColor Red
    exit 1
}

# Архив
Write-Host "[5/5] Создание архива..." -ForegroundColor Yellow
Compress-Archive -Path "dist\NetTopologyScanner" -DestinationPath "NetTopologyScanner_windows.zip" -Force

Write-Host ""
Write-Host "=== Готово! ===" -ForegroundColor Green
Write-Host "EXE: dist\NetTopologyScanner\NetTopologyScanner.exe"
Write-Host "ZIP: NetTopologyScanner_windows.zip"
Write-Host ""
Write-Host "Использование:"
Write-Host "  NetTopologyScanner.exe --subnet 192.168.1.0/24"
Write-Host "  NetTopologyScanner.exe --subnets 192.168.1.0/24 10.0.0.0/24 --no-gui --output result.json"
