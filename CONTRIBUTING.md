# Как внести вклад в проект

Спасибо за интерес к проекту! Любая помощь приветствуется.

## Сообщить об ошибке

1. Проверьте [Issues](https://github.com/ilyabem/networkscanner/issues) — возможно, баг уже известен.
2. Создайте новый Issue с:
   - Версией Python и ОС
   - Командой запуска
   - Выводом лога (с уровнем DEBUG: добавьте `--log-level DEBUG`)
   - Ожидаемым и фактическим поведением

## Предложить улучшение

Создайте Issue с тегом `enhancement` и опишите:
- Что хотите добавить и зачем
- Как это должно работать

## Pull Request

1. Форкните репозиторий
2. Создайте ветку: `git checkout -b feature/my-feature`
3. Внесите изменения
4. Убедитесь что тесты проходят: `pytest test_topology.py -v`
5. Обновите `CHANGELOG.md`
6. Отправьте PR в ветку `main`

## Структура проекта

| Файл | Назначение |
|---|---|
| `net_topology.py` | Точка входа, CLI-аргументы |
| `scanner.py` | ARP + nmap сканирование |
| `analyzer.py` | Классификация устройств |
| `model.py` | Модель данных, граф |
| `oui_db.py` | OUI-база производителей |
| `gui.py` | Интерфейс PyQt5 |
| `test_topology.py` | Тесты pytest |

## Добавить новый тип устройства

1. `model.py` — добавить в `DEVICE_TYPES`, `DEVICE_TYPE_LABELS`, `TYPE_COLORS`, `TYPE_SHAPES`, `DEVICE_TYPE_GROUPS`
2. `analyzer.py` — добавить паттерны в `KEYWORD_PATTERNS` и/или `PORT_WEIGHTS`
3. `oui_db.py` — добавить vendor-правила в `VENDOR_TYPE_RULES`
4. `test_topology.py` — добавить тесты

## Добавить нового производителя в OUI-базу

В файле `oui_db.py`, массив `VENDOR_TYPE_RULES`:

```python
([
    "название производителя",  # строчные буквы
], "device_type", weight),
```

Вес: 3.0–6.5 (чем специфичнее производитель → тип, тем выше).
