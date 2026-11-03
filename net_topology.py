#!/usr/bin/env python3
"""
net_topology.py — точка входа.

Установка:
    pip install -r requirements.txt

Внешние утилиты:
    nmap  — https://nmap.org/download.html
    Npcap — https://npcap.com/ (только Windows)

Использование:
    python net_topology.py --subnet  192.168.1.0/24
    python net_topology.py --subnets 192.168.1.0/24 10.0.0.0/24
    python net_topology.py --subnets 192.168.1.0/24,10.0.0.0/24 --parallel
    python net_topology.py --load topology.json
    python net_topology.py --subnet 192.168.1.0/24 --no-gui
    python net_topology.py --subnet 192.168.1.0/24 --no-gui --output result.json
    python net_topology.py --subnet 192.168.1.0/24 --no-gui --output result.json --output-graphml result.graphml
    python net_topology.py --subnet 192.168.1.0/24 --no-gui --export net.html --export net.drawio
    python net_topology.py --load topology.json --no-gui --layout tree-lr --export net.svg

Форматы --export (по расширению): .html .svg .drawio .graphml .csv .json
"""

import argparse
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("net_topology")


# ─── Аргументы ───────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Сканер и редактор топологии сети")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--subnet",  metavar="CIDR",
                   help="Одна подсеть, например 192.168.1.0/24")
    g.add_argument("--subnets", nargs="+", metavar="CIDR",
                   help="Несколько подсетей через пробел или запятую")
    p.add_argument("--community", default="public",
                   help="SNMP community string (по умолчанию: public)")
    p.add_argument("--no-gui",    action="store_true",
                   help="Только CLI-вывод, без GUI")
    p.add_argument("--max-hosts", type=int, default=254,
                   help="Макс. хостов на подсеть")
    p.add_argument("--load",      metavar="FILE",
                   help="Загрузить топологию из JSON")
    p.add_argument("--timeout",   type=float, default=1.0,
                   help="Таймаут ответа хоста (сек)")
    p.add_argument("--parallel",  action="store_true",
                   help="Параллельное сканирование подсетей")
    p.add_argument("--update-oui", action="store_true",
                   help="Обновить OUI-базу производителей и выйти")
    p.add_argument("--output",     metavar="FILE",
                   help="Сохранить топологию в JSON-файл (работает с --no-gui и без)")
    p.add_argument("--output-graphml", metavar="FILE",
                   help="Экспортировать топологию в GraphML-файл")
    p.add_argument("--export", metavar="FILE", action="append", default=[],
                   help="Экспорт по расширению: .html .svg .drawio .graphml "
                        ".csv .json (можно указать несколько раз)")
    p.add_argument("--layout", choices=["tree", "tree-lr", "organic"],
                   help="Раскладка схемы: tree (по умолчанию), tree-lr, "
                        "organic. С --load перекладывает загруженную схему")
    return p.parse_args()


def resolve_subnets(args: argparse.Namespace) -> list[str]:
    """Собирает список подсетей из --subnet / --subnets."""
    if args.subnet:
        return [args.subnet]
    if args.subnets:
        result = []
        for item in args.subnets:
            for part in item.split(","):
                part = part.strip()
                if part:
                    result.append(part)
        return result
    return []


# ─── Сканирование одной подсети ───────────────────────────────────────────────
# Вынесено в отдельную функцию, импортируется gui.py через lazy-import
# внутри ScanWorker.run() — чтобы избежать циклического импорта.

def scan_subnet(subnet: str, community: str,
                timeout: float, max_hosts: int):
    """
    Сканирует одну подсеть.
    Возвращает (subnet, hosts, arp_table).
    Импортирует scanner/analyzer здесь, не на уровне модуля.
    """
    from scanner  import NetworkScanner
    from analyzer import DeviceAnalyzer

    logger.info("▶ %s", subnet)
    scanner = NetworkScanner(subnet=subnet, timeout=timeout,
                             max_hosts=max_hosts, snmp_community=community)
    hosts   = scanner.scan()
    logger.info("◀ %s: %d хостов", subnet, len(hosts))

    analyzer = DeviceAnalyzer(snmp_community=community)
    for host in hosts:
        analyzer.enrich(host)

    # get_arp_table() — эвристика «все соседи шлюза», а не реальные данные:
    # связи теперь выводит модель (шлюз → коммутатор → устройства).
    return subnet, hosts, None


# ─── CLI-таблица ─────────────────────────────────────────────────────────────

def print_cli_table(topology) -> None:
    """
    Печатает таблицу устройств.
    Мультиинтерфейсные помечены *.
    """
    from model import DEVICE_TYPE_LABELS
    print("\n" + "=" * 84)
    print("  ОБНАРУЖЕННЫЕ УСТРОЙСТВА  (* = мультиинтерфейсное)")
    print("=" * 84)
    print(f"{'*':<2} {'IP':<18} {'MAC':<19} {'Тип':<18} {'Производитель':<22} Имя")
    print("-" * 84)
    for dev in topology.devices.values():
        mark  = "*" if dev.is_multihomed else " "
        label = DEVICE_TYPE_LABELS.get(dev.device_type, dev.device_type)
        print(f"{mark:<2} {dev.ip:<18} {dev.mac or '—':<19} "
              f"{label:<18} {dev.vendor or '—':<22} {dev.hostname or '—'}")
        if dev.is_multihomed:
            for iface in dev.interfaces:
                if iface.ip != dev.ip:
                    sn = f" [{iface.subnet}]" if iface.subnet else ""
                    nm = f" ({iface.iface_name})" if iface.iface_name else ""
                    print(f"   ↳ {iface.ip}{nm}{sn}")

    print("\n" + "=" * 84)
    print("  СВЯЗИ")
    print("=" * 84)
    if topology.links:
        for src, dst, attrs in topology.links:
            sd = topology.devices.get(src)
            dd = topology.devices.get(dst)
            print(f"  {(sd.ip if sd else src):<20} ── "
                  f"{(dd.ip if dd else dst):<20} [{attrs.get('label','')}]")
    else:
        print("  Связи не обнаружены")
    print()


# ─── Сохранение результатов ──────────────────────────────────────────────────

def _save_output(args: argparse.Namespace, topology) -> None:
    """
    Сохраняет топологию в JSON и/или GraphML.
    Вызывается в --no-gui режиме и опционально перед запуском GUI.

    Флаги:
      --output FILE          → topology.json
      --output-graphml FILE  → topology.graphml
    """
    import os

    output_path = getattr(args, "output", None)
    if output_path:
        if not output_path.endswith(".json"):
            output_path += ".json"
        try:
            topology.save_json(output_path)
            print(f"✓ Топология сохранена → {os.path.abspath(output_path)}")
        except Exception as exc:
            logger.error("Ошибка сохранения JSON: %s", exc)

    graphml_path = getattr(args, "output_graphml", None)
    if graphml_path:
        if not graphml_path.endswith(".graphml"):
            graphml_path += ".graphml"
        try:
            topology.export_graphml(graphml_path)
            print(f"✓ GraphML экспортирован → {os.path.abspath(graphml_path)}")
        except Exception as exc:
            logger.error("Ошибка экспорта GraphML: %s", exc)

    from exporters import export_topology
    for path in getattr(args, "export", None) or []:
        try:
            print(f"✓ Экспорт → {export_topology(topology, path)}")
        except Exception as exc:
            logger.error("Ошибка экспорта %s: %s", path, exc)


# ─── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    # Консоль Windows (cp1251/cp866/cp1252) не умеет «→», «★» и т.п.
    # При выводе в файл/канал кодировка берётся из локали (cp1252/cp1251) —
    # переключаемся на UTF-8, чтобы не терять кириллицу в логах.
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream.isatty():
                stream.reconfigure(errors="replace")
            else:
                stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
    args     = parse_args()
    # Импортируем модель здесь — gui импортируется только если нужен
    from model import NetworkTopology
    topology = NetworkTopology()
    topology.layout_mode = args.layout or "tree"

    # Обновление OUI-базы по запросу
    if getattr(args, 'update_oui', False):
        from oui_db import OUIDatabase
        db = OUIDatabase.get()
        ok = db.update_database()
        print(db.stats() if ok else 'Ошибка обновления OUI-базы')
        return

    if args.load:
        logger.info("Загрузка из %s", args.load)
        topology.load_json(args.load)
        if args.layout:
            topology.apply_layout(args.layout)

    else:
        subnets = resolve_subnets(args)

        if subnets:
            results = []
            if len(subnets) == 1 or not args.parallel:
                for s in subnets:
                    try:
                        results.append(scan_subnet(
                            s, args.community, args.timeout, args.max_hosts))
                    except PermissionError as e:
                        logger.error("Нет прав для %s: %s", s, e)
                    except Exception as e:
                        logger.error("Ошибка %s: %s", s, e)
            else:
                with ThreadPoolExecutor(max_workers=len(subnets)) as ex:
                    futures = {
                        ex.submit(scan_subnet, s, args.community,
                                  args.timeout, args.max_hosts): s
                        for s in subnets
                    }
                    for fut in as_completed(futures):
                        try:
                            results.append(fut.result())
                        except Exception as e:
                            logger.error("Ошибка %s: %s", futures[fut], e)

            if not results:
                logger.error("Ни одна подсеть не просканирована")
                sys.exit(1)

            if len(results) == 1:
                s, hosts, arp = results[0]
                topology.build_from_hosts(hosts, arp, subnet=s)
            else:
                topology.build_from_multi_subnet(results)
        else:
            logger.info("Подсети не указаны — пустая топология")

    if args.no_gui:
        print_cli_table(topology)
        _save_output(args, topology)
        return

    # Сохраняем если --output указан (даже с GUI — до его запуска)
    _save_output(args, topology)

    # GUI импортируется только здесь — нет циклического импорта
    from gui import run_gui
    logger.info("Запуск GUI")
    run_gui(topology, args.load)


if __name__ == "__main__":
    main()
