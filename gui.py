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

НОВОЕ v1.4:
  - Визуальные зоны подсетей (SubnetZone) — полупрозрачные прямоугольники с подписью CIDR.
  - Перетаскивание: ЛКМ = один узел, Shift+ЛКМ = вся подсеть.
  - Удаление связей: Ctrl+Click на линии связи.
  - Панель статистики: связи, активные IP, подсети.
  - Подсказки в статус-баре.
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
    QGraphicsLineItem, QGraphicsRectItem, QGraphicsScene, QGraphicsTextItem,
    QGraphicsView, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
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

# Бейджи открытых портов — отображаются рядом с иконкой узла
PORT_BADGES: dict[int, tuple[str, str, str]] = {
    3389: ("RDP",  "#e74c3c", "#ffffff"),
    22:   ("SSH",  "#2ecc71", "#ffffff"),
    23:   ("TEL",  "#e67e22", "#ffffff"),
    5900: ("VNC",  "#9b59b6", "#ffffff"),
    5985: ("WRM",  "#1abc9c", "#ffffff"),
}

RDP_TYPES = {"windows_endpoint", "windows_server", "endpoint", "unknown"}


# ═══════════════════════════════════════════════════════════════════════════
# Фоновый поток сканирования
# ═══════════════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════════════
# Виджет фильтра типов (выпадающий список с чекбоксами)
# ═══════════════════════════════════════════════════════════════════════════

class TypeFilterCombo(QComboBox):
    filter_changed = pyqtSignal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._checks: dict[str, QCheckBox] = {}
        self._container = QWidget(self)
        layout = QVBoxLayout(self._container)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(2)

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

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        layout.addWidget(line)

        for group_name, types in DEVICE_TYPE_GROUPS.items():
            lbl = QLabel(group_name)
            lbl.setStyleSheet("font-weight: bold; margin-top: 4px;")
            layout.addWidget(lbl)
            for dtype in types:
                cb = QCheckBox(DEVICE_TYPE_LABELS.get(dtype, dtype))
                cb.setChecked(True)
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
        return {t for t, cb in self._checks.items() if cb.isChecked()}

    def hidden_types(self) -> set[str]:
        return {t for t, cb in self._checks.items() if not cb.isChecked()}


# ═══════════════════════════════════════════════════════════════════════════
# SubnetZone — визуальная зона подсети
# ═══════════════════════════════════════════════════════════════════════════

class SubnetZone(QGraphicsRectItem):
    """Полупрозрачная зона подсети с подписью CIDR."""

    def __init__(self, cidr: str, parent=None) -> None:
        super().__init__(parent)
        self.cidr = cidr
        self._node_items: list = []
        self.setZValue(-100)          # Behind all nodes
        self.setPen(QPen(QColor(100, 100, 100, 150), 2, Qt.DashLine))

        # Generate color from CIDR hash
        import hashlib
        hue = int(hashlib.md5(cidr.encode()).hexdigest(), 16) % 360
        self._color = QColor.fromHsv(hue, 80, 230, 60)
        self.setBrush(QBrush(self._color))

        self._label = QGraphicsTextItem(self)
        self._label.setPlainText(f"  {cidr}  ")
        self._label.setFont(QFont("Arial", 10, QFont.Bold))
        self._label.setDefaultTextColor(QColor(50, 50, 50))
        self._label.hide()

    def update_geometry(self) -> None:
        if not self._node_items:
            self.setRect(0, 0, 0, 0)
            self._label.hide()
            self.hide()
            return

        rects = [item.sceneBoundingRect() for item in self._node_items
                 if item.scene() and item.isVisible()]
        if not rects:
            self.hide()
            return

        min_x = min(r.left() for r in rects)
        min_y = min(r.top() for r in rects)
        max_x = max(r.right() for r in rects)
        max_y = max(r.bottom() for r in rects)

        padding = 50
        self.setRect(
            min_x - padding,
            min_y - padding - 25,
            max_x - min_x + padding * 2,
            max_y - min_y + padding * 2 + 25,
        )
        self._label.setPos(min_x - padding + 5, min_y - padding - 20)
        self._label.show()
        self.show()

    def add_node(self, item) -> None:
        if item not in self._node_items:
            self._node_items.append(item)
            self.update_geometry()

    def remove_node(self, item) -> None:
        if item in self._node_items:
            self._node_items.remove(item)
            self.update_geometry()

    def clear(self) -> None:
        self._node_items.clear()
        self.update_geometry()


# ═══════════════════════════════════════════════════════════════════════════
# StatsOverlay — панель статистики
# ═══════════════════════════════════════════════════════════════════════════

class StatsOverlay(QGraphicsItem):
    """Панель статистики поверх сцены (связи, активные IP, подсети)."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setZValue(1000)
        self._bg = QGraphicsRectItem(self)
        self._bg.setBrush(QBrush(QColor(255, 255, 255, 220)))
        self._bg.setPen(QPen(QColor(100, 100, 100), 1))

        self._title = QGraphicsTextItem("📊 Статистика", self)
        self._title.setFont(QFont("Arial", 12, QFont.Bold))
        self._title.setDefaultTextColor(QColor(30, 30, 30))
        self._title.setPos(10, 5)

        self._links_text = QGraphicsTextItem("Связей: 0", self)
        self._links_text.setFont(QFont("Arial", 10))
        self._links_text.setDefaultTextColor(QColor(50, 50, 50))
        self._links_text.setPos(10, 30)

        self._active_text = QGraphicsTextItem("Активных IP: 0", self)
        self._active_text.setFont(QFont("Arial", 10))
        self._active_text.setDefaultTextColor(QColor(50, 150, 50))
        self._active_text.setPos(10, 50)

        self._subnets_text = QGraphicsTextItem("Подсетей: 0", self)
        self._subnets_text.setFont(QFont("Arial", 10))
        self._subnets_text.setDefaultTextColor(QColor(50, 50, 50))
        self._subnets_text.setPos(10, 70)

        self._update_size()

    def _update_size(self) -> None:
        self._bg.setRect(0, 0, 180, 95)

    def update_stats(self, links_count: int, active_ips: int, subnets_count: int) -> None:
        self._links_text.setPlainText(f"Связей: {links_count}")
        self._active_text.setPlainText(f"Активных IP: {active_ips}")
        self._subnets_text.setPlainText(f"Подсетей: {subnets_count}")

    def set_position(self, x: float, y: float) -> None:
        self.setPos(x, y)

    def boundingRect(self) -> QRectF:
        return QRectF(0, 0, 180, 95)

    def paint(self, painter: QPainter, option, widget=None) -> None:
        pass


# ═══════════════════════════════════════════════════════════════════════════
# NodeItem — узел с поддержкой перетаскивания одиночного / подсети
# ═══════════════════════════════════════════════════════════════════════════

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
        self._modifiers_at_press = Qt.NoModifier

    def _update_label(self) -> None:
        self._lbl.setPlainText(self.device.label())
        lw = self._lbl.boundingRect().width()
        self._lbl.setPos(-lw / 2, NODE_RADIUS + 4)

    def boundingRect(self) -> QRectF:
        r = NODE_RADIUS + (MULTIHOMED_BORDER_W + 2 if self.device.is_multihomed else 0)
        badge_space = 15 * len([p for p in PORT_BADGES if p in self.device.open_ports])
        badge_space = max(badge_space, 0)
        return QRectF(-r - 4, -r - 4 - badge_space,
                      (r + 4) * 2 + 36,
                      (r + 4) * 2 + 55 + badge_space)

    def paint(self, painter: QPainter, option, widget=None) -> None:
        color = QColor(TYPE_COLORS.get(self.device.device_type, "#bdc3c7"))
        if self._hovered:
            color = color.lighter(130)
        border = QColor("#2c3e50") if self.isSelected() else QColor("#7f8c8d")
        bw     = 3 if self.isSelected() else 1.5
        r      = NODE_RADIUS
        shape  = TYPE_SHAPES.get(self.device.device_type, "circle")

        if self.device.is_multihomed:
            painter.setPen(QPen(QColor(MULTIHOMED_BORDER_CLR),
                                MULTIHOMED_BORDER_W, Qt.DashLine))
            painter.setBrush(Qt.NoBrush)
            _draw_shape(painter, shape, r + MULTIHOMED_BORDER_W + 2)

        painter.setPen(QPen(border, bw))
        painter.setBrush(QBrush(color))
        _draw_shape(painter, shape, r)

        painter.setPen(QPen(Qt.white if _is_dark(color) else Qt.black))
        painter.setFont(QFont("Arial", 7, QFont.Bold))
        painter.drawText(QRectF(-r, -r, r * 2, r * 2),
                         Qt.AlignCenter, self.device.ip)

        self._paint_port_badges(painter, r)

    def _paint_port_badges(self, painter: QPainter, r: float) -> None:
        dev   = self.device
        ports = set(dev.open_ports)
        dtype = dev.device_type
        if not ports:
            return

        visible_ports = []
        for port, (label, bg, fg) in PORT_BADGES.items():
            if port not in ports:
                continue
            if port == 3389 and dtype not in RDP_TYPES:
                continue
            if port == 22 and dtype not in {
                "linux_server", "linux_endpoint", "router",
                "switch", "firewall", "server", "unknown"
            }:
                continue
            if port == 23 and dtype not in {"router", "switch", "bridge", "unknown"}:
                continue
            visible_ports.append((port, label, bg, fg))

        if not visible_ports:
            return

        badge_w  = 28
        badge_h  = 13
        badge_r  = 3
        margin   = 2
        start_x  = r - badge_w // 2 + 6
        start_y  = -r - badge_h - 2

        painter.setFont(QFont("Arial", 6, QFont.Bold))

        for i, (port, label, bg_hex, fg_hex) in enumerate(visible_ports):
            bx = start_x
            by = start_y + i * (badge_h + margin)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(QColor(bg_hex)))
            painter.drawRoundedRect(
                QRectF(bx, by, badge_w, badge_h), badge_r, badge_r
            )
            painter.setPen(QPen(QColor(fg_hex)))
            painter.drawText(
                QRectF(bx, by, badge_w, badge_h),
                Qt.AlignCenter,
                label
            )

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionHasChanged:
            p = self.pos()
            self.device.position = (p.x(), p.y())
            scene = self.scene()
            if scene and hasattr(scene, "update_edges_for_node"):
                scene.update_edges_for_node(self.device.node_id)
            if scene and hasattr(scene, "update_subnet_zone"):
                scene.update_subnet_zone(self.device.subnet)
        return super().itemChange(change, value)

    def mousePressEvent(self, event) -> None:
        self._modifiers_at_press = event.modifiers()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:
        if self._modifiers_at_press & Qt.ShiftModifier:
            delta = event.scenePos() - event.lastScenePos()
            scene = self.scene()
            if scene and hasattr(scene, "move_subnet"):
                scene.move_subnet(self.device.subnet, delta)
            event.accept()
        else:
            super().mouseMoveEvent(event)

    def hoverEnterEvent(self, e):
        self._hovered = True;  self.update(); super().hoverEnterEvent(e)

    def hoverLeaveEvent(self, e):
        self._hovered = False; self.update(); super().hoverLeaveEvent(e)

    def refresh(self) -> None:
        self._update_label()
        self.prepareGeometryChange()
        self.update()


# ═══════════════════════════════════════════════════════════════════════════
# EdgeItem — связь с удалением по Ctrl+Click
# ═══════════════════════════════════════════════════════════════════════════

class EdgeItem(QGraphicsLineItem):
    def __init__(self, src: NodeItem, dst: NodeItem, label: str = "") -> None:
        super().__init__()
        self.src_node   = src
        self.dst_node   = dst
        self.edge_label = label
        self.setZValue(-1)
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.setAcceptHoverEvents(True)
        self._hovered = False
        self.update_position()

    def update_position(self) -> None:
        s, d = self.src_node.pos(), self.dst_node.pos()
        self.setLine(s.x(), s.y(), d.x(), d.y())

    def hoverEnterEvent(self, event) -> None:
        self._hovered = True
        self.setCursor(Qt.PointingHandCursor)
        self.update()
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event) -> None:
        self._hovered = False
        self.unsetCursor()
        self.update()
        super().hoverLeaveEvent(event)

    def mousePressEvent(self, event) -> None:
        if event.modifiers() & Qt.ControlModifier:
            scene = self.scene()
            if scene and hasattr(scene, "delete_edge"):
                scene.delete_edge(
                    self.src_node.device.node_id,
                    self.dst_node.device.node_id
                )
            event.accept()
        else:
            super().mousePressEvent(event)

    def paint(self, painter, option, widget=None) -> None:
        if self.edge_label == "inter-subnet":
            pen = QPen(QColor("#e74c3c"), 2, Qt.DashDotLine)
        elif self.isSelected() or self._hovered:
            pen = QPen(QColor("#e74c3c"), 2.5, Qt.DashLine)
        else:
            pen = QPen(QColor("#7f8c8d"), 1.5, Qt.SolidLine)
        self.setPen(pen)
        super().paint(painter, option, widget)


# ═══════════════════════════════════════════════════════════════════════════
# TopologyScene — основная сцена
# ═══════════════════════════════════════════════════════════════════════════

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
        self._subnet_zones: dict[str, SubnetZone] = {}
        self._link_mode = False
        self._link_src: Optional[NodeItem] = None
        self._stats = StatsOverlay()
        self.addItem(self._stats)
        self._active_ips: set[str] = set()
        self._rebuild()

    # ── Построение ─────────────────────────────────────────────────────────

    def _rebuild(self) -> None:
        self.clear()
        self._node_items.clear()
        self._edge_items.clear()
        self._subnet_zones.clear()
        self._stats = StatsOverlay()
        self.addItem(self._stats)

        for dev in self.topology.devices.values():
            item = self._add_node_item(dev)
            item.setVisible(dev.device_type in self._visible_types)
        for src, dst, attrs in self.topology.links:
            self._add_edge_item(src, dst, attrs.get("label", ""))

        self._update_stats()
        self._update_stats_position()

    def _add_node_item(self, device: Device) -> NodeItem:
        item = NodeItem(device)
        self.addItem(item)
        self._node_items[device.node_id] = item

        # Add to subnet zone
        subnet = device.subnet or "unknown"
        if subnet not in self._subnet_zones:
            zone = SubnetZone(subnet)
            self._subnet_zones[subnet] = zone
            self.addItem(zone)
        self._subnet_zones[subnet].add_node(item)

        return item

    def _add_edge_item(self, src_id: str, dst_id: str,
                       label: str = "") -> Optional[EdgeItem]:
        si = self._node_items.get(src_id)
        di = self._node_items.get(dst_id)
        if not si or not di:
            return None
        edge = EdgeItem(si, di, label)
        edge.setVisible(si.isVisible() and di.isVisible())
        self.addItem(edge)
        self._edge_items.append(edge)
        return edge

    # ── Фильтрация ─────────────────────────────────────────────────────────

    def apply_filter(self, visible_types: set[str]) -> None:
        self._visible_types = visible_types
        for nid, item in self._node_items.items():
            dev = self.topology.devices.get(nid)
            visible = dev.device_type in visible_types if dev else True
            item.setVisible(visible)
        for edge in self._edge_items:
            edge.setVisible(
                edge.src_node.isVisible() and edge.dst_node.isVisible()
            )
        # Update all subnet zones
        for zone in self._subnet_zones.values():
            zone.update_geometry()
        self._update_stats()

    # ── Обновление рёбер при перемещении узла ──────────────────────────────

    def update_edges_for_node(self, node_id: str) -> None:
        for edge in self._edge_items:
            if (edge.src_node.device.node_id == node_id or
                    edge.dst_node.device.node_id == node_id):
                edge.update_position()

    # ── Перемещение подсети (Shift+Drag) ───────────────────────────────────

    def move_subnet(self, subnet: str, delta: QPointF) -> None:
        for node in self._node_items.values():
            if node.device.subnet == subnet:
                node.moveBy(delta.x(), delta.y())
        self.update_subnet_zone(subnet)
        # Update all edges (nodes in subnet may be connected to outside)
        for edge in self._edge_items:
            edge.update_position()

    def update_subnet_zone(self, subnet: str) -> None:
        zone = self._subnet_zones.get(subnet)
        if zone:
            zone.update_geometry()

    # ── Удаление связи (Ctrl+Click) ────────────────────────────────────────

    def delete_edge(self, src_id: str, dst_id: str) -> None:
        to_remove = [e for e in self._edge_items
                     if (e.src_node.device.node_id == src_id and
                         e.dst_node.device.node_id == dst_id) or
                        (e.src_node.device.node_id == dst_id and
                         e.dst_node.device.node_id == src_id)]
        for edge in to_remove:
            if edge.scene():
                self.removeItem(edge)
            self._edge_items.remove(edge)
        # Also remove from topology model
        self.topology.remove_link(src_id, dst_id)
        self.topology_changed.emit()
        self._update_stats()

    # ── Добавление / удаление ──────────────────────────────────────────────

    def add_device(self, device: Device) -> None:
        self.topology.add_device(device)
        item = self._add_node_item(device)
        item.setVisible(device.device_type in self._visible_types)
        self.topology_changed.emit()
        self._update_stats()

    def add_link_between(self, src_id: str, dst_id: str,
                         label: str = "manual") -> None:
        self.topology.add_link(src_id, dst_id, label)
        self._add_edge_item(src_id, dst_id, label)
        self.topology_changed.emit()
        self._update_stats()

    def delete_device(self, node_id: str) -> None:
        to_rm = [e for e in self._edge_items
                 if e.src_node.device.node_id == node_id
                 or e.dst_node.device.node_id == node_id]
        for e in to_rm:
            self.removeItem(e); self._edge_items.remove(e)
        item = self._node_items.pop(node_id, None)
        if item:
            # Remove from subnet zone
            subnet = item.device.subnet or "unknown"
            if subnet in self._subnet_zones:
                self._subnet_zones[subnet].remove_node(item)
            self.removeItem(item)
        self.topology.remove_device(node_id)
        self.topology_changed.emit()
        self._update_stats()

    def delete_selected_edge(self) -> None:
        for edge in list(self._edge_items):
            if edge.isSelected():
                self.topology.remove_link(
                    edge.src_node.device.node_id,
                    edge.dst_node.device.node_id)
                self.removeItem(edge)
                self._edge_items.remove(edge)
        self.topology_changed.emit()
        self._update_stats()

    # ── Объединение / разделение ───────────────────────────────────────────

    def merge_nodes(self, primary_id: str, secondary_id: str) -> None:
        if self.topology.merge_devices(primary_id, secondary_id):
            to_rm = [e for e in self._edge_items
                     if e.src_node.device.node_id == secondary_id
                     or e.dst_node.device.node_id == secondary_id]
            for e in to_rm:
                self.removeItem(e); self._edge_items.remove(e)
            item = self._node_items.pop(secondary_id, None)
            if item:
                subnet = item.device.subnet or "unknown"
                if subnet in self._subnet_zones:
                    self._subnet_zones[subnet].remove_node(item)
                self.removeItem(item)
            pi = self._node_items.get(primary_id)
            if pi:
                pi.refresh()
            self._rebuild_edges()
            self.topology_changed.emit()
            self._update_stats()

    def split_node(self, node_id: str, split_ip: str) -> None:
        new_id = self.topology.split_device(node_id, split_ip)
        if new_id:
            new_dev = self.topology.devices[new_id]
            base = self._node_items[node_id].pos()
            new_dev.position = (base.x() + 120, base.y() + 80)
            ni = self._add_node_item(new_dev)
            ni.setVisible(new_dev.device_type in self._visible_types)
            pi = self._node_items.get(node_id)
            if pi:
                pi.refresh()
            self.topology_changed.emit()
            self._update_stats()

    def _rebuild_edges(self) -> None:
        for e in self._edge_items:
            self.removeItem(e)
        self._edge_items.clear()
        for src, dst, attrs in self.topology.links:
            self._add_edge_item(src, dst, attrs.get("label", ""))

    # ── Режим связи ────────────────────────────────────────────────────────

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

    # ── Контекстное меню ───────────────────────────────────────────────────

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
                self.delete_edge(
                    edge.src_node.device.node_id,
                    edge.dst_node.device.node_id)
        else:
            add_a = menu.addAction("➕  Добавить устройство")
            if menu.exec_(event.screenPos()) == add_a:
                dev = Device(ip="0.0.0.0")
                d   = DeviceEditDialog(dev, self.topology)
                if d.exec_() == QDialog.Accepted:
                    dev.position = (event.scenePos().x(), event.scenePos().y())
                    self.add_device(dev)

    # ── Статистика ─────────────────────────────────────────────────────────

    def set_active_ips(self, ips: set[str]) -> None:
        self._active_ips = ips
        self._update_stats()

    def _update_stats(self) -> None:
        links = len(self._edge_items)
        active = len(self._active_ips)
        subnets = len(self._subnet_zones)
        self._stats.update_stats(links, active, subnets)

    def _update_stats_position(self) -> None:
        if self.views():
            view = self.views()[0]
            viewport = view.viewport()
            top_right = view.mapToScene(viewport.width() - 200, 10)
            self._stats.set_position(top_right.x(), top_right.y())


# ═══════════════════════════════════════════════════════════════════════════
# Диалоги
# ═══════════════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════════════
# MainWindow
# ═══════════════════════════════════════════════════════════════════════════

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

    # ── UI ─────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root   = QWidget()
        self.setCentralWidget(root)
        vlayout = QVBoxLayout(root)
        vlayout.setContentsMargins(0, 0, 0, 0)

        # ── Панель управления ────────────────────────────────────────────
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

        self.type_filter = TypeFilterCombo()
        self.type_filter.filter_changed.connect(self._on_filter_changed)

        self.link_btn = QPushButton("🔗 Связь")
        self.link_btn.setCheckable(True)
        self.link_btn.clicked.connect(self._toggle_link_mode)

        self.fit_btn  = QPushButton("⊡ Вписать")
        self.fit_btn.setToolTip("Вписать всю схему в экран (Ctrl+F)")
        self.fit_btn.clicked.connect(self._fit_view)

        self.zoom_in_btn  = QPushButton("🔍+")
        self.zoom_out_btn = QPushButton("🔍−")
        self.zoom_in_btn.setMaximumWidth(36)
        self.zoom_out_btn.setMaximumWidth(36)
        self.zoom_in_btn.setToolTip("Увеличить (+)")
        self.zoom_out_btn.setToolTip("Уменьшить (−)")
        self.zoom_in_btn.clicked.connect(lambda: self.view.scale(1.25, 1.25))
        self.zoom_out_btn.clicked.connect(lambda: self.view.scale(0.8, 0.8))

        cl.addWidget(QLabel("Подсети:"))
        cl.addWidget(self.subnets_edit)
        cl.addWidget(QLabel("Community:"))
        cl.addWidget(self.community_edit)
        cl.addWidget(self.parallel_cb)
        cl.addWidget(self.scan_btn)
        cl.addSpacing(16)
        cl.addWidget(self.type_filter)
        cl.addWidget(self.link_btn)
        cl.addSpacing(8)
        cl.addWidget(self.fit_btn)
        cl.addWidget(self.zoom_in_btn)
        cl.addWidget(self.zoom_out_btn)
        cl.addStretch()
        vlayout.addWidget(ctrl)

        # ── Граф ──────────────────────────────────────────────────────────
        self.view = QGraphicsView()
        self.view.setRenderHint(QPainter.Antialiasing)
        self.view.setDragMode(QGraphicsView.RubberBandDrag)
        self.view.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.view.setResizeAnchor(QGraphicsView.AnchorUnderMouse)
        self.view.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.view.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.view.setScene(None)
        vlayout.addWidget(self.view)

        # ── Подсказки в статус-баре ─────────────────────────────────────
        self._help_label = QLabel(
            "🖱️ ЛКМ — перемещение узла  |  "
            "🖱️ Shift+ЛКМ — перемещение подсети  |  "
            "🖱️ Ctrl+Click на связи — удаление  |  "
            "🖱️ ПКМ — контекстное меню  |  "
            "🖱️ Колёсико — масштаб"
        )
        self.statusBar().addPermanentWidget(self._help_label)
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
        vm.addAction("Вписать в экран",   self._fit_view,       "Ctrl+F")
        vm.addAction("Сбросить масштаб",  self._reset_zoom,     "Ctrl+0")
        vm.addAction("Увеличить",         lambda: self.view.scale(1.25, 1.25), "+")
        vm.addAction("Уменьшить",         lambda: self.view.scale(0.80, 0.80), "-")
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
        from PyQt5.QtCore import QTimer
        QTimer.singleShot(100, self._fit_view)

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
            f"Скрытых: {hidden}{oui_info}",
            0
        )
        # Keep help label visible
        self.statusBar().addPermanentWidget(self._help_label)

    def _on_filter_changed(self) -> None:
        self._scene.apply_filter(self.type_filter.visible_types())
        self._update_status()

    # ── Сканирование ───────────────────────────────────────────────────────

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
        # Collect active IPs from scanned topology
        active_ips = {dev.ip for dev in topology.devices.values()}
        self._refresh_scene()
        self._scene.set_active_ips(active_ips)
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

    # ── Файлы ──────────────────────────────────────────────────────────────

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
        self._scene._update_stats_position()

    def _reset_zoom(self) -> None:
        self.view.resetTransform()

    def wheelEvent(self, event) -> None:
        f = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.view.scale(f, f)

    def keyPressEvent(self, event) -> None:
        from PyQt5.QtCore import Qt as _Qt
        key = event.key()
        if key == _Qt.Key_Space:
            self.view.setDragMode(QGraphicsView.ScrollHandDrag)
        elif key in (_Qt.Key_Plus, _Qt.Key_Equal):
            self.view.scale(1.25, 1.25)
        elif key == _Qt.Key_Minus:
            self.view.scale(0.80, 0.80)
        elif key == _Qt.Key_F:
            self._fit_view()
        else:
            super().keyPressEvent(event)

    def keyReleaseEvent(self, event) -> None:
        from PyQt5.QtCore import Qt as _Qt
        if event.key() == _Qt.Key_Space:
            self.view.setDragMode(QGraphicsView.RubberBandDrag)
        else:
            super().keyReleaseEvent(event)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if hasattr(self, '_scene') and self._scene:
            self._scene._update_stats_position()

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


# ═══════════════════════════════════════════════════════════════════════════
# Вспомогательные
# ═══════════════════════════════════════════════════════════════════════════

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