@echo off
:: ============================================================
:: build_windows.bat — сборка NetTopologyScanner.exe
:: Запускать от имени Администратора в папке проекта
:: ============================================================

echo === Сборка NetTopologyScanner для Windows ===
echo.

:: Проверяем Python
python --version 2>nul
if errorlevel 1 (
    echo [ОШИБКА] Python не найден. Установите Python 3.10+ с https://python.org
    pause
    exit /b 1
)

:: Создаём виртуальное окружение
echo [1/5] Создание виртуального окружения...
python -m venv venv_build
call venv_build\Scripts\activate.bat

:: Устанавливаем зависимости
echo [2/5] Установка зависимостей...
pip install --upgrade pip -q
pip install pyinstaller -q
pip install PyQt5 networkx numpy python-nmap scapy pysnmp==4.4.12 mac-vendor-lookup -q

echo [3/5] Проверка установки...
python -c "import PyQt5, networkx, numpy, nmap; print('OK — все зависимости установлены')"
if errorlevel 1 (
    echo [ОШИБКА] Не все зависимости установлены
    pause
    exit /b 1
)

:: Сборка exe
echo [4/5] Сборка exe...
pyinstaller net_topology.spec --clean --noconfirm

if not exist "dist\NetTopologyScanner\NetTopologyScanner.exe" (
    echo [ОШИБКА] Сборка не удалась — exe не создан
    pause
    exit /b 1
)

:: Создаём архив для распространения
echo [5/5] Создание архива...
powershell -Command "Compress-Archive -Path 'dist\NetTopologyScanner' -DestinationPath 'NetTopologyScanner_windows.zip' -Force"

echo.
echo === Готово! ===
echo Исполняемый файл: dist\NetTopologyScanner\NetTopologyScanner.exe
echo Архив для распространения: NetTopologyScanner_windows.zip
echo.
echo Использование:
echo   dist\NetTopologyScanner\NetTopologyScanner.exe --subnet 192.168.1.0/24
echo   dist\NetTopologyScanner\NetTopologyScanner.exe --subnet 192.168.1.0/24 --no-gui
echo.
pause
