"""
gui.py — графический интерфейс редактора топологии (PyQt5).

НОВОЕ:
  - Боковая панель с выпадающим фильтром типов устройств (QComboBox с чекбоксами).
    Скрывает узлы и их связи мгновенно, без пересканирования.
    Связи между двумя скрытыми узлами тоже скрываются.
    Связи от скрытого узла к видимому — скрываются тоже.
  - Расширенные типы устройств (windows_server, linux_server, windows_endpoint,
    linux_endpoint, printer) с новыми цветами и подписями.
  - Мультиинтерфейсные узлы: двойная золотистая рамка + ★.
  - Сканирование в фоновом QThread — GUI не зависает.
  - Исправлен циклический импорт: scan_subnet импортируется внутри ScanWorker.run().
"""

from __future__ import annotations

import logging
import math
import sys
from typing import Optional

from PyQt5.QtCore import Qt, QPointF, QRectF, QThread, pyqtSignal
from PyQt5.QtGui import QBrush, QColor, QFont, QPainter, QPen, QPolygonF
from PyQt5.QtWidgets import (
    QAction, QApplication, QCheckBox, QComboBox, QDialog,
    QDialogButtonBox, QFileDialog, QFormLayout, QGraphicsItem,
    QGraphicsLineItem, QGraphicsScene, QGraphicsTextItem, QGraphicsView,
    QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QMainWindow, QMenu, QMessageBox, QPushButton, QSplitter,
    QTextEdit, QVBoxLayout, QWidget, QFrame,
)

from model import (Device, Interface, NetworkTopology,
                   DEVICE_TYPES, DEVICE_TYPE_LABELS,
                   DEVICE_TYPE_GROUPS, TYPE_COLORS, TYPE_SHAPES)

logger = logging.getLogger("gui")

NODE_RADIUS           = 28
FONT_SIZE             = 8
MULTIHOMED_BORDER_CLR = "#f39c12"
MULTIHOMED_BORDER_W   = 4


# ─── Фоновый поток сканирования ──────────────────────────────────────────────

class ScanWorker(QThread):
    """Сканирование в фоне; lazy-импорт scan_subnet устраняет цикл."""
    finished = pyqtSignal(object)
    error    = pyqtSignal(str)

    def __init__(self, subnets: list[str], community: str,
                 parallel: bool = False) -> None:
        super().__init__()
        self.subnets   = subnets
        self.community = community
        self.parallel  = parallel

    def run(self) -> None:
        try:
            # Lazy-импорт: net_topology уже не импортирует gui на уровне модуля
            from net_topology import scan_subnet
            from concurrent.futures import ThreadPoolExecutor, as_completed
            from model import NetworkTopology

            results = []
            if self.parallel and len(self.subnets) > 1:
                with ThreadPoolExecutor(max_workers=len(self.subnets)) as ex:
                    futs = {
                        ex.submit(scan_subnet, s, self.community, 1.0, 254): s
                        for s in self.subnets
                    }
                    for fut in as_completed(futs):
                        try:
                            results.append(fut.result())
                        except Exception as e:
                            logger.warning("Ошибка %s: %s", futs[fut], e)
            else:
                for s in self.subnets:
                    try:
                        results.append(scan_subnet(s, self.community, 1.0, 254))
                    except Exception as e:
                        logger.warning("Ошибка %s: %s", s, e)

            topo = NetworkTopology()
            if len(results) == 1:
                s, hosts, arp = results[0]
                topo.build_from_hosts(hosts, arp, subnet=s)
            elif len(results) > 1:
                topo.build_from_multi_subnet(results)
            self.finished.emit(topo)
        except Exception as e:
            self.error.emit(str(e))


# ─── Виджет фильтра типов (выпадающий список с чекбоксами) ──────────────────

class TypeFilterCombo(QComboBox):
    """
    Выпадающий список с чекбоксами для каждого типа устройства.
    Сгруппирован по категориям (сетевое оборудование / серверы / точки).
    При изменении выбора испускает сигнал filter_changed.
    """
    filter_changed = pyqtSignal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._checks: dict[str, QCheckBox] = {}   # тип → чекбокс
        self._container = QWidget(self)
        layout = QVBoxLayout(self._container)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(2)

        # Кнопки «Все» / «Ничего»
        btn_row = QWidget()
        btn_layout = QHBoxLayout(btn_row)
        btn_layout.setContentsMargins(0, 0, 0, 0)
        all_btn  = QPushButton("Все")
        none_btn = QPushButton("Скрыть все")
        all_btn.setMaximumHeight(22)
        none_btn.setMaximumHeight(22)
        all_btn.clicked.connect(self._check_all)
        none_btn.clicked.connect(self._uncheck_all)
        btn_layout.addWidget(all_btn)
        btn_layout.addWidget(none_btn)
        layout.addWidget(btn_row)

        # Разделитель
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        layout.addWidget(line)

        # Чекбоксы по группам
        for group_name, types in DEVICE_TYPE_GROUPS.items():
            lbl = QLabel(group_name)
            lbl.setStyleSheet("font-weight: bold; margin-top: 4px;")
            layout.addWidget(lbl)
            for dtype in types:
                cb = QCheckBox(DEVICE_TYPE_LABELS.get(dtype, dtype))
                cb.setChecked(True)
                # Цветная точка через таблицу стилей
                color = TYPE_COLORS.get(dtype, "#aaa")
                cb.setStyleSheet(
                    f"QCheckBox::indicator:checked {{ background: {color}; "
                    f"border: 1px solid #555; border-radius: 2px; }}"
                )
                cb.stateChanged.connect(self._on_change)
                self._checks[dtype] = cb
                layout.addWidget(cb)

        self._container.adjustSize()
        self.setMinimumWidth(220)
        self.addItem("🔽 Фильтр типов устройств")

    def showPopup(self) -> None:
        """Показываем наш виджет вместо стандартного выпадающего."""
        self._container.setWindowFlags(Qt.Popup)
        pos = self.mapToGlobal(QPointF(0, self.height()).toPoint())
        self._container.move(pos)
        self._container.show()

    def hidePopup(self) -> None:
        self._container.hide()
        super().hidePopup()

    def _on_change(self) -> None:
        hidden = self.hidden_types()
        n = len(hidden)
        if n == 0:
            self.setItemText(0, "🔽 Показаны все типы")
        else:
            labels = [DEVICE_TYPE_LABELS.get(t, t) for t in hidden]
            self.setItemText(0, f"🔽 Скрыто: {', '.join(labels)}")
        self.filter_changed.emit()

    def _check_all(self) -> None:
        for cb in self._checks.values():
            cb.blockSignals(True)
            cb.setChecked(True)
            cb.blockSignals(False)
        self._on_change()

    def _uncheck_all(self) -> None:
        for cb in self._checks.values():
            cb.blockSignals(True)
            cb.setChecked(False)
            cb.blockSignals(False)
        self._on_change()

    def visible_types(self) -> set[str]:
        """Набор типов, которые сейчас отмечены (видимы)."""
        return {t for t, cb in self._checks.items() if cb.isChecked()}

    def hidden_types(self) -> set[str]:
        return {t for t, cb in self._checks.items() if not cb.isChecked()}


# ─── NodeItem ────────────────────────────────────────────────────────────────

class NodeItem(QGraphicsItem):
    """Узел на сцене. Мультиинтерфейсный — двойная золотая рамка."""

    def __init__(self, device: Device, parent=None) -> None:
        super().__init__(parent)
        self.device   = device
        self._hovered = False
        self.setFlag(QGraphicsItem.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.setFlag(QGraphicsItem.ItemSendsGeometryChanges, True)
        self.setAcceptHoverEvents(True)
        if device.position:
            self.setPos(device.position[0], device.position[1])
        self._lbl = QGraphicsTextItem(self)
        self._lbl.setFont(QFont("Arial", FONT_SIZE))
        self._update_label()

    def _update_label(self) -> None:
        self._lbl.setPlainText(self.device.label())
        lw = self._lbl.boundingRect().width()
        self._lbl.setPos(-lw / 2, NODE_RADIUS + 4)

    def boundingRect(self) -> QRectF:
        r = NODE_RADIUS + (MULTIHOMED_BORDER_W + 2 if self.device.is_multihomed else 0)
        return QRectF(-r - 4, -r - 4, (r + 4) * 2, (r + 4) * 2 + 55)

    def paint(self, painter: QPainter, option, widget=None) -> None:
        color = QColor(TYPE_COLORS.get(self.device.device_type, "#bdc3c7"))
        if self._hovered:
            color = color.lighter(130)
        border = QColor("#2c3e50") if self.isSelected() else QColor("#7f8c8d")
        bw     = 3 if self.isSelected() else 1.5
        r      = NODE_RADIUS
        shape  = TYPE_SHAPES.get(self.device.device_type, "circle")

        # Двойная рамка для мультиинтерфейсных
        if self.device.is_multihomed:
            painter.setPen(QPen(QColor(MULTIHOMED_BORDER_CLR),
                                MULTIHOMED_BORDER_W, Qt.DashLine))
            painter.setBrush(Qt.NoBrush)
            _draw_shape(painter, shape, r + MULTIHOMED_BORDER_W + 2)

        painter.setPen(QPen(border, bw))
        painter.setBrush(QBrush(color))
        _draw_shape(painter, shape, r)

        # IP внутри
        painter.setPen(QPen(Qt.white if _is_dark(color) else Qt.black))
        painter.setFont(QFont("Arial", 7, QFont.Bold))
        painter.drawText(QRectF(-r, -r, r * 2, r * 2),
                         Qt.AlignCenter, self.device.ip)

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionHasChanged:
            p = self.pos()
            self.device.position = (p.x(), p.y())
            scene = self.scene()
            if scene and hasattr(scene, "update_edges_for_node"):
                scene.update_edges_for_node(self.device.node_id)
        return super().itemChange(change, value)

    def hoverEnterEvent(self, e):
        self._hovered = True;  self.update(); super().hoverEnterEvent(e)

    def hoverLeaveEvent(self, e):
        self._hovered = False; self.update(); super().hoverLeaveEvent(e)

    def refresh(self) -> None:
        self._update_label()
        self.prepareGeometryChange()
        self.update()


# ─── EdgeItem ────────────────────────────────────────────────────────────────

class EdgeItem(QGraphicsLineItem):
    def __init__(self, src: NodeItem, dst: NodeItem, label: str = "") -> None:
        super().__init__()
        self.src_node   = src
        self.dst_node   = dst
        self.edge_label = label
        self.setZValue(-1)
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.update_position()

    def update_position(self) -> None:
        s, d = self.src_node.pos(), self.dst_node.pos()
        self.setLine(s.x(), s.y(), d.x(), d.y())

    def paint(self, painter, option, widget=None) -> None:
        if self.edge_label == "inter-subnet":
            pen = QPen(QColor("#e74c3c"), 2, Qt.DashDotLine)
        elif self.isSelected():
            pen = QPen(QColor("#e74c3c"), 2.5, Qt.DashLine)
        else:
            pen = QPen(QColor("#7f8c8d"), 1.5, Qt.SolidLine)
        self.setPen(pen)
        super().paint(painter, option, widget)


# ─── TopologyScene ────────────────────────────────────────────────────────────

class TopologyScene(QGraphicsScene):
    topology_changed = pyqtSignal()

    def __init__(self, topology: NetworkTopology,
                 visible_types: set[str] | None = None,
                 parent=None) -> None:
        super().__init__(parent)
        self.topology      = topology
        self._visible_types: set[str] = visible_types or set(DEVICE_TYPES)
        self._node_items: dict[str, NodeItem] = {}
        self._edge_items: list[EdgeItem]       = []
        self._link_mode = False
        self._link_src: Optional[NodeItem] = None
        self._rebuild()

    # ── Построение ───────────────────────────────────────────────────────────

    def _rebuild(self) -> None:
        self.clear()
        self._node_items.clear()
        self._edge_items.clear()
        for dev in self.topology.devices.values():
            item = self._add_node_item(dev)
            # Скрываем если тип не в видимых
            item.setVisible(dev.device_type in self._visible_types)
        for src, dst, attrs in self.topology.links:
            edge = self._add_edge_item(src, dst, attrs.get("label", ""))

    def _add_node_item(self, device: Device) -> NodeItem:
        item = NodeItem(device)
        self.addItem(item)
        self._node_items[device.node_id] = item
        return item

    def _add_edge_item(self, src_id: str, dst_id: str,
                       label: str = "") -> Optional[EdgeItem]:
        si = self._node_items.get(src_id)
        di = self._node_items.get(dst_id)
        if not si or not di:
            return None
        edge = EdgeItem(si, di, label)
        # Связь видима только если оба конца видимы
        edge.setVisible(si.isVisible() and di.isVisible())
        self.addItem(edge)
        self._edge_items.append(edge)
        return edge

    # ── Фильтрация ───────────────────────────────────────────────────────────

    def apply_filter(self, visible_types: set[str]) -> None:
        """
        Показывает/скрывает узлы и рёбра по набору видимых типов.
        Не пересоздаёт сцену — только меняет visible у существующих элементов.
        """
        self._visible_types = visible_types
        for nid, item in self._node_items.items():
            dev     = self.topology.devices.get(nid)
            visible = dev.device_type in visible_types if dev else True
            item.setVisible(visible)
        # Рёбра видимы только если оба конца видимы
        for edge in self._edge_items:
            edge.setVisible(
                edge.src_node.isVisible() and edge.dst_node.isVisible()
            )

    # ── Обновление рёбер при перемещении узла ────────────────────────────────

    def update_edges_for_node(self, node_id: str) -> None:
        for edge in self._edge_items:
            if (edge.src_node.device.node_id == node_id or
                    edge.dst_node.device.node_id == node_id):
                edge.update_position()

    # ── Добавление / удаление ────────────────────────────────────────────────

    def add_device(self, device: Device) -> None:
        self.topology.add_device(device)
        item = self._add_node_item(device)
        item.setVisible(device.device_type in self._visible_types)
        self.topology_changed.emit()

    def add_link_between(self, src_id: str, dst_id: str,
                         label: str = "manual") -> None:
        self.topology.add_link(src_id, dst_id, label)
        self._add_edge_item(src_id, dst_id, label)
        self.topology_changed.emit()

    def delete_device(self, node_id: str) -> None:
        to_rm = [e for e in self._edge_items
                 if e.src_node.device.node_id == node_id
                 or e.dst_node.device.node_id == node_id]
        for e in to_rm:
            self.removeItem(e); self._edge_items.remove(e)
        item = self._node_items.pop(node_id, None)
        if item:
            self.removeItem(item)
        self.topology.remove_device(node_id)
        self.topology_changed.emit()

    def delete_selected_edge(self) -> None:
        for edge in list(self._edge_items):
            if edge.isSelected():
                self.topology.remove_link(
                    edge.src_node.device.node_id,
                    edge.dst_node.device.node_id)
                self.removeItem(edge)
                self._edge_items.remove(edge)
        self.topology_changed.emit()

    # ── Объединение / разделение ─────────────────────────────────────────────

    def merge_nodes(self, primary_id: str, secondary_id: str) -> None:
        if self.topology.merge_devices(primary_id, secondary_id):
            to_rm = [e for e in self._edge_items
                     if e.src_node.device.node_id == secondary_id
                     or e.dst_node.device.node_id == secondary_id]
            for e in to_rm:
                self.removeItem(e); self._edge_items.remove(e)
            item = self._node_items.pop(secondary_id, None)
            if item:
                self.removeItem(item)
            pi = self._node_items.get(primary_id)
            if pi:
                pi.refresh()
            self._rebuild_edges()
            self.topology_changed.emit()

    def split_node(self, node_id: str, split_ip: str) -> None:
        new_id = self.topology.split_device(node_id, split_ip)
        if new_id:
            new_dev = self.topology.devices[new_id]
            base    = self._node_items[node_id].pos()
            new_dev.position = (base.x() + 120, base.y() + 80)
            ni = self._add_node_item(new_dev)
            ni.setVisible(new_dev.device_type in self._visible_types)
            pi = self._node_items.get(node_id)
            if pi:
                pi.refresh()
            self.topology_changed.emit()

    def _rebuild_edges(self) -> None:
        for e in self._edge_items:
            self.removeItem(e)
        self._edge_items.clear()
        for src, dst, attrs in self.topology.links:
            self._add_edge_item(src, dst, attrs.get("label", ""))

    # ── Режим связи ──────────────────────────────────────────────────────────

    def start_link_mode(self) -> None:
        self._link_mode = True; self._link_src = None

    def stop_link_mode(self) -> None:
        self._link_mode = False; self._link_src = None

    def mousePressEvent(self, event) -> None:
        if self._link_mode and event.button() == Qt.LeftButton:
            items = self.items(event.scenePos())
            node  = next((i for i in items
                          if isinstance(i, NodeItem) and i.isVisible()), None)
            if node:
                if self._link_src is None:
                    self._link_src = node
                else:
                    if self._link_src.device.node_id != node.device.node_id:
                        self.add_link_between(
                            self._link_src.device.node_id,
                            node.device.node_id)
                    self.stop_link_mode()
            return
        super().mousePressEvent(event)

    # ── Контекстное меню ─────────────────────────────────────────────────────

    def contextMenuEvent(self, event) -> None:
        items = self.items(event.scenePos())
        node  = next((i for i in items if isinstance(i, NodeItem)), None)
        edge  = next((i for i in items if isinstance(i, EdgeItem)), None)
        menu  = QMenu()

        if node:
            dev = node.device
            menu.addSection(
                f"{'★ ' if dev.is_multihomed else ''}"
                f"{dev.ip}  [{DEVICE_TYPE_LABELS.get(dev.device_type, dev.device_type)}]"
            )
            edit_a  = menu.addAction("✏️  Редактировать...")
            del_a   = menu.addAction("🗑️  Удалить")
            link_a  = menu.addAction("🔗  Добавить связь")
            menu.addSeparator()
            merge_a = menu.addAction("🔀  Объединить с узлом...")
            split_a = menu.addAction("✂️  Разделить интерфейс...")
            split_a.setEnabled(dev.is_multihomed)
            action  = menu.exec_(event.screenPos())
            if action == edit_a:
                d = DeviceEditDialog(dev, self.topology)
                if d.exec_() == QDialog.Accepted:
                    node.refresh(); self.topology_changed.emit()
            elif action == del_a:
                if QMessageBox.question(
                        None, "Удалить?", f"Удалить {dev.ip}?",
                        QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
                    self.delete_device(dev.node_id)
            elif action == link_a:
                self._link_src = node; self.start_link_mode()
                self._link_src = node
            elif action == merge_a:
                d = MergeDialog(dev, self.topology)
                if d.exec_() == QDialog.Accepted and d.selected_id:
                    self.merge_nodes(dev.node_id, d.selected_id)
            elif action == split_a:
                d = SplitDialog(dev)
                if d.exec_() == QDialog.Accepted and d.selected_ip:
                    self.split_node(dev.node_id, d.selected_ip)

        elif edge:
            del_e = menu.addAction("🗑️  Удалить связь")
            if menu.exec_(event.screenPos()) == del_e:
                edge.setSelected(True); self.delete_selected_edge()
        else:
            add_a = menu.addAction("➕  Добавить устройство")
            if menu.exec_(event.screenPos()) == add_a:
                dev = Device(ip="0.0.0.0")
                d   = DeviceEditDialog(dev, self.topology)
                if d.exec_() == QDialog.Accepted:
                    dev.position = (event.scenePos().x(), event.scenePos().y())
                    self.add_device(dev)


# ─── Диалоги ─────────────────────────────────────────────────────────────────

class DeviceEditDialog(QDialog):
    def __init__(self, device: Device, topology: NetworkTopology,
                 parent=None) -> None:
        super().__init__(parent)
        self.device   = device
        self.topology = topology
        self.setWindowTitle("Редактирование устройства")
        self.setMinimumWidth(400)
        layout = QFormLayout(self)

        self.ip_edit       = QLineEdit(device.ip)
        self.hostname_edit = QLineEdit(device.hostname or "")
        self.mac_edit      = QLineEdit(device.mac or "")
        self.subnet_edit   = QLineEdit(device.subnet or "")
        self.notes_edit    = QLineEdit(device.notes)

        self.type_combo = QComboBox()
        for t in DEVICE_TYPES:
            self.type_combo.addItem(
                DEVICE_TYPE_LABELS.get(t, t), t)
        idx = DEVICE_TYPES.index(device.device_type) \
            if device.device_type in DEVICE_TYPES else 0
        self.type_combo.setCurrentIndex(idx)

        layout.addRow("IP-адрес:",       self.ip_edit)
        layout.addRow("Имя хоста:",      self.hostname_edit)
        layout.addRow("MAC-адрес:",      self.mac_edit)
        layout.addRow("Подсеть (CIDR):", self.subnet_edit)
        layout.addRow("Тип:",            self.type_combo)
        layout.addRow("Заметки:",        self.notes_edit)

        if device.is_multihomed or len(device.interfaces) > 1:
            ta = QTextEdit(); ta.setReadOnly(True); ta.setMaximumHeight(90)
            ta.setPlainText(device.interfaces_label())
            layout.addRow("Все IP:", ta)

        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self._apply); bb.rejected.connect(self.reject)
        layout.addRow(bb)

    def _apply(self) -> None:
        self.device.ip          = self.ip_edit.text().strip() or self.device.ip
        self.device.hostname    = self.hostname_edit.text().strip() or None
        self.device.mac         = self.mac_edit.text().strip() or None
        self.device.subnet      = self.subnet_edit.text().strip()
        self.device.device_type = self.type_combo.currentData()
        self.device.notes       = self.notes_edit.text().strip()
        self.accept()


class MergeDialog(QDialog):
    def __init__(self, device: Device, topology: NetworkTopology,
                 parent=None) -> None:
        super().__init__(parent)
        self.selected_id: Optional[str] = None
        self.setWindowTitle(f"Объединить {device.ip} с...")
        self.setMinimumWidth(320)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Выберите узел:"))
        self.lw = QListWidget()
        for nid, dev in topology.devices.items():
            if nid == device.node_id:
                continue
            lbl  = DEVICE_TYPE_LABELS.get(dev.device_type, dev.device_type)
            item = QListWidgetItem(f"{dev.ip}  [{lbl}]  {dev.hostname or ''}")
            item.setData(Qt.UserRole, nid)
            self.lw.addItem(item)
        layout.addWidget(self.lw)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self._apply); bb.rejected.connect(self.reject)
        layout.addWidget(bb)

    def _apply(self) -> None:
        it = self.lw.currentItem()
        if it:
            self.selected_id = it.data(Qt.UserRole); self.accept()


class SplitDialog(QDialog):
    def __init__(self, device: Device, parent=None) -> None:
        super().__init__(parent)
        self.selected_ip: Optional[str] = None
        self.setWindowTitle(f"Разделить {device.ip}")
        self.setMinimumWidth(300)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Выберите IP для отделения:"))
        self.lw = QListWidget()
        for iface in device.interfaces:
            if iface.ip == device.ip:
                continue
            lbl  = iface.ip
            if iface.subnet:    lbl += f"  [{iface.subnet}]"
            if iface.iface_name: lbl += f"  ({iface.iface_name})"
            item = QListWidgetItem(lbl)
            item.setData(Qt.UserRole, iface.ip)
            self.lw.addItem(item)
        layout.addWidget(self.lw)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self._apply); bb.rejected.connect(self.reject)
        layout.addWidget(bb)

    def _apply(self) -> None:
        it = self.lw.currentItem()
        if it:
            self.selected_ip = it.data(Qt.UserRole); self.accept()


# ─── MainWindow ──────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self, topology: NetworkTopology) -> None:
        super().__init__()
        self.topology       = topology
        self._current_file: Optional[str] = None
        self._modified      = False
        self._worker: Optional[ScanWorker] = None

        self.setWindowTitle("Редактор топологии сети")
        self.resize(1280, 820)
        self._build_ui()
        self._build_menu()
        self._refresh_scene()

    # ── UI ───────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root   = QWidget()
        self.setCentralWidget(root)
        vlayout = QVBoxLayout(root)
        vlayout.setContentsMargins(0, 0, 0, 0)

        # ── Панель управления ────────────────────────────────────────────────
        ctrl = QWidget()
        cl   = QHBoxLayout(ctrl)
        cl.setContentsMargins(6, 4, 6, 4)

        self.subnets_edit = QLineEdit()
        self.subnets_edit.setPlaceholderText(
            "192.168.1.0/24, 10.0.0.0/24  (через запятую или пробел)")
        self.subnets_edit.setMinimumWidth(280)

        self.community_edit = QLineEdit("public")
        self.community_edit.setMaximumWidth(100)

        self.parallel_cb = QCheckBox("Параллельно")

        self.scan_btn = QPushButton("▶ Сканировать")
        self.scan_btn.clicked.connect(self._on_scan)

        # Фильтр типов
        self.type_filter = TypeFilterCombo()
        self.type_filter.filter_changed.connect(self._on_filter_changed)

        self.link_btn = QPushButton("🔗 Связь")
        self.link_btn.setCheckable(True)
        self.link_btn.clicked.connect(self._toggle_link_mode)

        cl.addWidget(QLabel("Подсети:"))
        cl.addWidget(self.subnets_edit)
        cl.addWidget(QLabel("Community:"))
        cl.addWidget(self.community_edit)
        cl.addWidget(self.parallel_cb)
        cl.addWidget(self.scan_btn)
        cl.addSpacing(16)
        cl.addWidget(self.type_filter)
        cl.addWidget(self.link_btn)
        cl.addStretch()
        vlayout.addWidget(ctrl)

        # ── Граф ────────────────────────────────────────────────────────────
        self.view = QGraphicsView()
        self.view.setRenderHint(QPainter.Antialiasing)
        self.view.setDragMode(QGraphicsView.RubberBandDrag)
        self.view.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        vlayout.addWidget(self.view)

        self.statusBar().showMessage("Готово")

    def _build_menu(self) -> None:
        mb = self.menuBar()
        fm = mb.addMenu("Файл")
        fm.addAction("Открыть...",         self._open_file,      "Ctrl+O")
        fm.addAction("Сохранить",          self._save_file,      "Ctrl+S")
        fm.addAction("Сохранить как...",   self._save_as,        "Ctrl+Shift+S")
        fm.addSeparator()
        fm.addAction("Экспорт GraphML...", self._export_graphml)
        fm.addSeparator()
        fm.addAction("Выход", self.close)

        em = mb.addMenu("Правка")
        em.addAction("Добавить устройство...", self._add_device_dialog)
        em.addAction("Удалить выбранную связь",
                     self._delete_selected_edge, "Delete")
        em.addSeparator()
        em.addAction("Объединить по MAC (авто)", self._auto_merge)
        em.addSeparator()
        em.addAction("🔄 Обновить OUI-базу...", self._update_oui_db)

        vm = mb.addMenu("Вид")
        vm.addAction("Вписать в экран",  self._fit_view,    "Ctrl+F")
        vm.addAction("Сбросить масштаб", self._reset_zoom,  "Ctrl+0")
        vm.addSeparator()
        vm.addAction("Показать все типы", self.type_filter._check_all)
        vm.addAction("Скрыть все типы",   self.type_filter._uncheck_all)

    # ── Сцена ────────────────────────────────────────────────────────────────

    def _refresh_scene(self) -> None:
        vt    = self.type_filter.visible_types()
        scene = TopologyScene(self.topology, visible_types=vt)
        scene.topology_changed.connect(self._on_changed)
        self.view.setScene(scene)
        self._scene = scene
        self._update_status()

    def _on_changed(self) -> None:
        self._modified = True
        self._update_status()
        self.setWindowTitle(
            f"Редактор топологии — "
            f"{self._current_file or 'без имени'}"
            f"{'*' if self._modified else ''}"
        )

    def _update_status(self) -> None:
        total  = len(self.topology.devices)
        multi  = sum(1 for d in self.topology.devices.values()
                     if d.is_multihomed)
        hidden = len(self.type_filter.hidden_types())
        # Информация об OUI-базе
        oui_info = ""
        try:
            from oui_db import OUIDatabase
            db = OUIDatabase.get()
            if db._loaded and db.size > 0:
                oui_info = f" | OUI: {db.size:,} записей"
        except Exception:
            pass
        self.statusBar().showMessage(
            f"Устройств: {total}  (мульти: {multi}) | "
            f"Связей: {len(self.topology.links)} | "
            f"Скрытых: {hidden}{oui_info}"
        )

    def _on_filter_changed(self) -> None:
        """Применяем фильтр к существующей сцене без пересоздания."""
        self._scene.apply_filter(self.type_filter.visible_types())
        self._update_status()

    # ── Сканирование ─────────────────────────────────────────────────────────

    def _on_scan(self) -> None:
        raw = self.subnets_edit.text().strip()
        if not raw:
            QMessageBox.warning(self, "Предупреждение",
                                "Введите хотя бы одну подсеть")
            return
        subnets = [p.strip()
                   for p in raw.replace(",", " ").split() if p.strip()]
        self.scan_btn.setEnabled(False)
        self.statusBar().showMessage(
            f"Сканирование {len(subnets)} подсет(и/ей)...")
        self._worker = ScanWorker(
            subnets   = subnets,
            community = self.community_edit.text().strip() or "public",
            parallel  = self.parallel_cb.isChecked(),
        )
        self._worker.finished.connect(self._on_scan_done)
        self._worker.error.connect(self._on_scan_error)
        self._worker.start()

    def _on_scan_done(self, topology: NetworkTopology) -> None:
        self.topology = topology
        self._refresh_scene()
        self.scan_btn.setEnabled(True)
        multi = sum(1 for d in topology.devices.values() if d.is_multihomed)
        self.statusBar().showMessage(
            f"Готово. Устройств: {len(topology.devices)}, "
            f"мультиинтерфейсных: {multi}"
        )

    def _on_scan_error(self, msg: str) -> None:
        self.scan_btn.setEnabled(True)
        QMessageBox.critical(self, "Ошибка сканирования", msg)

    # ── Правка ───────────────────────────────────────────────────────────────

    def _add_device_dialog(self) -> None:
        dev = Device(ip="0.0.0.0")
        d   = DeviceEditDialog(dev, self.topology, self)
        if d.exec_() == QDialog.Accepted:
            dev.position = (400, 300)
            self._scene.add_device(dev)

    def _delete_selected_edge(self) -> None:
        self._scene.delete_selected_edge()

    def _auto_merge(self) -> None:
        n = self.topology.merge_by_mac()
        self._refresh_scene()
        QMessageBox.information(self, "Объединение по MAC",
                                f"Объединено групп: {n}")

    def _update_oui_db(self) -> None:
        """Запускает обновление OUI-базы в фоне и показывает прогресс."""
        from PyQt5.QtCore import QThread, pyqtSignal as _sig

        class OUIWorker(QThread):
            done = _sig(bool, str)
            def run(self):
                try:
                    from oui_db import OUIDatabase
                    db = OUIDatabase.get()
                    ok = db.update_database()
                    self.done.emit(ok, db.stats())
                except Exception as e:
                    self.done.emit(False, str(e))

        self._oui_worker = OUIWorker()
        def on_done(ok, msg):
            if ok:
                QMessageBox.information(self, "OUI-база обновлена", msg)
            else:
                QMessageBox.warning(self, "Ошибка OUI", msg)
        self._oui_worker.done.connect(on_done)
        self.statusBar().showMessage("Обновление OUI-базы...")
        self._oui_worker.start()

    def _toggle_link_mode(self, checked: bool) -> None:
        if checked:
            self._scene.start_link_mode()
            self.statusBar().showMessage(
                "Режим связи: кликните первый узел, затем второй")
        else:
            self._scene.stop_link_mode()
            self._update_status()

    # ── Файлы ────────────────────────────────────────────────────────────────

    def _open_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Открыть", "", "JSON (*.json);;Все (*)")
        if path:
            self.topology.load_json(path)
            self._current_file = path
            self._modified     = False
            self._refresh_scene()

    def _save_file(self) -> None:
        if not self._current_file:
            self._save_as(); return
        self.topology.save_json(self._current_file)
        self._modified = False
        self.setWindowTitle(
            f"Редактор топологии — {self._current_file}")

    def _save_as(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить как", "topology.json", "JSON (*.json)")
        if path:
            self._current_file = path; self._save_file()

    def _export_graphml(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт GraphML", "topology.graphml",
            "GraphML (*.graphml)")
        if path:
            self.topology.export_graphml(path)
            self.statusBar().showMessage(f"Экспортировано: {path}")

    # ── Вид ──────────────────────────────────────────────────────────────────

    def _fit_view(self) -> None:
        self.view.fitInView(self._scene.sceneRect(), Qt.KeepAspectRatio)

    def _reset_zoom(self) -> None:
        self.view.resetTransform()

    def wheelEvent(self, event) -> None:
        f = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.view.scale(f, f)

    def closeEvent(self, event) -> None:
        if self._modified:
            r = QMessageBox.question(
                self, "Несохранённые изменения",
                "Сохранить перед выходом?",
                QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel)
            if r == QMessageBox.Save:
                self._save_file()
            elif r == QMessageBox.Cancel:
                event.ignore(); return
        event.accept()


# ─── Вспомогательные ─────────────────────────────────────────────────────────

def _draw_shape(painter: QPainter, shape: str, r: float) -> None:
    if shape == "circle":
        painter.drawEllipse(QRectF(-r, -r, r * 2, r * 2))
    elif shape == "square":
        painter.drawRect(QRectF(-r, -r, r * 2, r * 2))
    elif shape == "diamond":
        painter.drawPolygon(QPolygonF([
            QPointF(0, -r), QPointF(r, 0),
            QPointF(0,  r), QPointF(-r, 0)]))
    elif shape == "triangle":
        painter.drawPolygon(QPolygonF([
            QPointF(0, -r), QPointF(r, r), QPointF(-r, r)]))
    elif shape == "hexagon":
        pts = [QPointF(r * math.cos(math.radians(60*i - 30)),
                       r * math.sin(math.radians(60*i - 30)))
               for i in range(6)]
        painter.drawPolygon(QPolygonF(pts))
    else:
        painter.drawEllipse(QRectF(-r, -r, r * 2, r * 2))


def _is_dark(c: QColor) -> bool:
    return 0.299 * c.red() + 0.587 * c.green() + 0.114 * c.blue() < 128


def run_gui(topology: NetworkTopology) -> None:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("Net Topology Editor")
    app.setStyle("Fusion")
    w = MainWindow(topology)
    w.show()
    sys.exit(app.exec_())
