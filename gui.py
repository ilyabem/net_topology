"""
gui.py — графический интерфейс редактора топологии (PyQt5).

Окно:
  * Центр — схема: карточки устройств с векторными иконками, зоны подсетей,
    связи с маршрутами без пересечения узлов. Колесо — масштаб под курсором,
    средняя кнопка / пробел — панорама, при сильном отдалении подписи
    скрываются (схема остаётся читаемой).
  * Слева — «Сканирование» (подсети, параметры, прогресс, остановка) и
    «Устройства» (дерево по подсетям с поиском; клик — показать на схеме).
  * Справа — «Свойства» выбранного устройства с пояснением классификации.
  * Снизу — «Журнал» сканирования.
  * Панель инструментов: файл, экспорт (HTML/SVG/PDF/PNG/draw.io/GraphML/CSV),
    раскладка, масштаб, режим связи, фильтр типов, поиск.

Перетаскивание: ЛКМ — узел, Shift+ЛКМ — вся подсеть.
Ctrl+клик по связи или Delete — удалить. ПКМ — контекстное меню.
Настройки и расположение панелей сохраняются между запусками.
"""

from __future__ import annotations

import html
import logging
import os
import socket
import sys
from typing import Optional

from PyQt5.QtCore import (QByteArray, QObject, QPointF, QRectF, QSettings,
                          QSize, Qt, QThread, QTimer, pyqtSignal)
from PyQt5.QtGui import (QBrush, QColor, QFont, QFontMetricsF, QIcon,
                         QImage, QKeySequence, QPainter, QPainterPath,
                         QPainterPathStroker, QPen, QPixmap)
from PyQt5.QtSvg import QSvgRenderer
from PyQt5.QtWidgets import (
    QAbstractItemView, QAction, QActionGroup, QApplication, QCheckBox,
    QComboBox, QDialog, QDialogButtonBox, QDockWidget, QDoubleSpinBox,
    QFileDialog, QFormLayout, QGraphicsItem, QGraphicsPathItem,
    QGraphicsRectItem, QGraphicsScene, QGraphicsSimpleTextItem,
    QGraphicsView, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QMainWindow, QMenu, QMessageBox, QPlainTextEdit,
    QProgressBar, QPushButton, QSpinBox, QStyle, QTextBrowser, QToolButton,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from exporters import EXPORT_FORMATS, export_topology
from layout import LAYOUT_MODES, NODE_H, NODE_W
from model import (APP_NAME, APP_VERSION, DEVICE_TYPE_GROUPS,
                   DEVICE_TYPE_LABELS, DEVICE_TYPES, Device, NetworkTopology,
                   ip_sort_key)
from visual import (BADGE_H, BADGE_W, DETAIL_Y, ICON_SIZE, ICON_TOP, IP_Y,
                    TITLE_Y, ZONE_LABEL_H, card_badges, card_lines,
                    device_tooltip, icon_svg, link_label, link_style,
                    subnet_color, zone_members, zone_rect)

logger = logging.getLogger("gui")

ORG_NAME = "NetTopology"
SETTINGS_APP = "NetTopologyEditor"

LOD_TEXT = 0.38            # ниже этого масштаба подписи на карточках скрыты
COLOR_SELECTED = QColor("#2471a3")
COLOR_HIT = QColor("#f1c40f")
COLOR_CARD = QColor("#ffffff")
COLOR_BORDER = QColor("#d5d8dc")
COLOR_MULTI = QColor("#f39c12")


# ═══════════════════════════════════════════════════════════════════════════
# Иконки (SVG → QSvgRenderer, кэш по типу)
# ═══════════════════════════════════════════════════════════════════════════

_RENDERERS: dict[str, QSvgRenderer] = {}
_ICONS: dict[str, QIcon] = {}


def type_renderer(device_type: str) -> QSvgRenderer:
    r = _RENDERERS.get(device_type)
    if r is None:
        r = QSvgRenderer(QByteArray(icon_svg(device_type).encode("utf-8")))
        _RENDERERS[device_type] = r
    return r


def type_icon(device_type: str, size: int = 32) -> QIcon:
    key = f"{device_type}:{size}"
    icon = _ICONS.get(key)
    if icon is None:
        pm = QPixmap(size, size)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.Antialiasing)
        type_renderer(device_type).render(p, QRectF(0, 0, size, size))
        p.end()
        icon = QIcon(pm)
        _ICONS[key] = icon
    return icon


# ═══════════════════════════════════════════════════════════════════════════
# Журнал → GUI (потокобезопасно через сигнал)
# ═══════════════════════════════════════════════════════════════════════════

class _LogBridge(QObject):
    message = pyqtSignal(str)


class QtLogHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.INFO)
        self.bridge = _LogBridge()
        self.setFormatter(logging.Formatter(
            "%(asctime)s  %(levelname)-7s %(name)s: %(message)s", "%H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.bridge.message.emit(self.format(record))
        except RuntimeError:       # окно уже закрыто
            pass


# ═══════════════════════════════════════════════════════════════════════════
# Фоновое сканирование
# ═══════════════════════════════════════════════════════════════════════════

class ScanWorker(QThread):
    """Сканирует подсети в фоне. Остановка — между подсетями."""
    progress = pyqtSignal(int, int, str)
    finished_ok = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, subnets: list[str], community: str,
                 parallel: bool = False, timeout: float = 1.0,
                 max_hosts: int = 254, layout_mode: str = "tree") -> None:
        super().__init__()
        self.subnets = subnets
        self.community = community
        self.parallel = parallel
        self.timeout = timeout
        self.max_hosts = max_hosts
        self.layout_mode = layout_mode

    def run(self) -> None:
        try:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            from net_topology import scan_subnet

            total = len(self.subnets)
            results = []
            done = 0
            self.progress.emit(0, total, "Запуск сканирования…")
            if self.parallel and total > 1:
                with ThreadPoolExecutor(max_workers=min(total, 4)) as ex:
                    futs = {ex.submit(scan_subnet, s, self.community,
                                      self.timeout, self.max_hosts): s
                            for s in self.subnets}
                    for fut in as_completed(futs):
                        done += 1
                        try:
                            results.append(fut.result())
                        except Exception as e:  # noqa: BLE001
                            logger.warning("Ошибка %s: %s", futs[fut], e)
                        self.progress.emit(done, total,
                                           f"Готово: {futs[fut]}")
                        if self.isInterruptionRequested():
                            for f in futs:
                                f.cancel()
                            break
            else:
                for s in self.subnets:
                    if self.isInterruptionRequested():
                        break
                    self.progress.emit(done, total, f"Сканирование {s}…")
                    try:
                        results.append(scan_subnet(s, self.community,
                                                   self.timeout,
                                                   self.max_hosts))
                    except PermissionError as e:
                        logger.error("Нет прав для %s: %s", s, e)
                    except Exception as e:  # noqa: BLE001
                        logger.warning("Ошибка %s: %s", s, e)
                    done += 1

            if self.isInterruptionRequested():
                logger.info("Сканирование остановлено пользователем")
            self.progress.emit(done, total, "Построение схемы…")
            topo = NetworkTopology()
            topo.layout_mode = self.layout_mode
            if results:
                topo.build_from_multi_subnet(results)
            self.finished_ok.emit(topo)
        except Exception as e:  # noqa: BLE001
            logger.exception("Сбой сканирования")
            self.failed.emit(str(e))


def guess_local_subnet() -> str:
    """Подсеть /24 основного интерфейса (без отправки пакетов)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))     # UDP connect ничего не отправляет
        ip = s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()
    if ip.startswith("127."):
        return ""
    return ip.rsplit(".", 1)[0] + ".0/24"


# ═══════════════════════════════════════════════════════════════════════════
# Элементы сцены
# ═══════════════════════════════════════════════════════════════════════════

class SubnetZone(QGraphicsRectItem):
    """Полупрозрачная зона подсети с подписью «CIDR · N»."""

    def __init__(self, cidr: str) -> None:
        super().__init__()
        self.cidr = cidr
        self.node_ids: list[str] = []
        self.setZValue(-100)
        r, g, b = subnet_color(cidr)
        fill = QColor(r, g, b, 72)
        stroke = QColor(int(r * .6), int(g * .6), int(b * .6), 180)
        self.setBrush(QBrush(fill))
        pen = QPen(stroke, 1.5, Qt.DashLine)
        pen.setCosmetic(True)
        self.setPen(pen)
        self._label = QGraphicsSimpleTextItem(self)
        f = QFont()
        f.setPointSizeF(10)
        f.setBold(True)
        self._label.setFont(f)
        self._label.setBrush(QBrush(QColor("#2c3e50")))

    def update_geometry(self, items: dict[str, "NodeItem"]) -> None:
        pts = [items[n].pos() for n in self.node_ids
               if n in items and items[n].isVisible()]
        if not pts:
            self.hide()
            return
        x, y, w, h = zone_rect([(p.x(), p.y()) for p in pts])
        self.setRect(QRectF(x, y, w, h))
        self._label.setText(f"{self.cidr}  ·  {len(pts)}")
        self._label.setPos(x + 10, y + (ZONE_LABEL_H - 16) / 2 + 2)
        self.show()


class NodeItem(QGraphicsItem):
    """Карточка устройства: иконка, имя, IP, «производитель · ОС», бейджи."""

    def __init__(self, device: Device) -> None:
        super().__init__()
        self.device = device
        self.highlighted = False
        self.dimmed = False
        self._hovered = False
        self._press_mods = Qt.NoModifier
        self.setFlags(QGraphicsItem.ItemIsMovable
                      | QGraphicsItem.ItemIsSelectable
                      | QGraphicsItem.ItemSendsGeometryChanges)
        self.setAcceptHoverEvents(True)
        self.setCacheMode(QGraphicsItem.DeviceCoordinateCache)
        self.setZValue(10)
        if device.position:
            self.setPos(device.position[0], device.position[1])
        self.refresh()

    # ── геометрия ──

    _RECT = QRectF(-NODE_W / 2, -NODE_H / 2, NODE_W, NODE_H)

    def boundingRect(self) -> QRectF:
        return self._RECT.adjusted(-4, -4, 4, 6)

    def shape(self) -> QPainterPath:
        path = QPainterPath()
        path.addRoundedRect(self._RECT, 10, 10)
        return path

    def refresh(self) -> None:
        self.setToolTip(device_tooltip(self.device))
        self.update()

    def set_state(self, highlighted: bool, dimmed: bool) -> None:
        if (highlighted, dimmed) != (self.highlighted, self.dimmed):
            self.highlighted, self.dimmed = highlighted, dimmed
            self.update()

    # ── отрисовка ──

    def paint(self, painter: QPainter, option, widget=None) -> None:
        dev = self.device
        lod = option.levelOfDetailFromTransform(painter.worldTransform())
        rect = self._RECT
        painter.setRenderHint(QPainter.Antialiasing)
        if self.dimmed:
            painter.setOpacity(0.22)

        # Тень и карточка
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(0, 0, 0, 28))
        painter.drawRoundedRect(rect.translated(0, 2), 10, 10)
        if self.isSelected():
            pen = QPen(COLOR_SELECTED, 3)
        elif self.highlighted:
            pen = QPen(COLOR_HIT, 4)
        elif dev.is_multihomed:
            pen = QPen(COLOR_MULTI, 2)
        else:
            pen = QPen(COLOR_BORDER.darker(115) if self._hovered
                       else COLOR_BORDER, 1.2)
        if dev.is_virtual:
            pen.setStyle(Qt.DashLine)
        painter.setPen(pen)
        painter.setBrush(COLOR_CARD)
        painter.drawRoundedRect(rect, 10, 10)

        icon_rect = QRectF(-ICON_SIZE / 2, rect.top() + ICON_TOP,
                           ICON_SIZE, ICON_SIZE)
        if lod < LOD_TEXT:
            # Издалека — только крупная иконка: схема остаётся читаемой
            big = QRectF(-NODE_H / 2 + 8, -NODE_H / 2 + 8,
                         NODE_H - 16, NODE_H - 16)
            type_renderer(dev.device_type).render(painter, big)
            return
        type_renderer(dev.device_type).render(painter, icon_rect)

        title, ip_line, detail = card_lines(dev)
        width = NODE_W - 12
        self._text(painter, title, TITLE_Y, 8.6, True, "#1c2833", width)
        self._text(painter, ip_line, IP_Y, 7.8, False, "#34495e", width)
        self._text(painter, detail, DETAIL_Y, 7.0, False, "#7f8c8d", width)

        left, right = card_badges(dev)
        f = QFont()
        f.setPointSizeF(6.2)
        f.setBold(True)
        painter.setFont(f)
        for i, b in enumerate(left):
            self._badge(painter, b, rect.left() + 6,
                        rect.top() + 6 + i * (BADGE_H + 3))
        for i, b in enumerate(right):
            self._badge(painter, b, rect.right() - BADGE_W - 6,
                        rect.top() + 6 + i * (BADGE_H + 3))

    @staticmethod
    def _text(painter: QPainter, text: str, baseline: float, size: float,
              bold: bool, color: str, width: float) -> None:
        f = QFont()
        f.setPointSizeF(size)
        f.setBold(bold)
        painter.setFont(f)
        fm = QFontMetricsF(f)
        text = fm.elidedText(text, Qt.ElideRight, width)
        painter.setPen(QColor(color))
        y = -NODE_H / 2 + baseline
        painter.drawText(QPointF(-fm.horizontalAdvance(text) / 2, y), text)

    @staticmethod
    def _badge(painter: QPainter, b, x: float, y: float) -> None:
        r = QRectF(x, y, BADGE_W, BADGE_H)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(b.bg))
        painter.drawRoundedRect(r, 4, 4)
        painter.setPen(QColor(b.fg))
        painter.drawText(r, Qt.AlignCenter, b.text)

    # ── взаимодействие ──

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionHasChanged:
            p = self.pos()
            self.device.position = (round(p.x(), 2), round(p.y(), 2))
            scene = self.scene()
            if isinstance(scene, TopologyScene):
                scene.node_moved(self)
        return super().itemChange(change, value)

    def mousePressEvent(self, event) -> None:
        self._press_mods = event.modifiers()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:
        if self._press_mods & Qt.ShiftModifier:
            scene = self.scene()
            if isinstance(scene, TopologyScene):
                scene.move_subnet(self.device.subnet,
                                  event.scenePos() - event.lastScenePos())
            event.accept()
        else:
            super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        super().mouseReleaseEvent(event)
        scene = self.scene()
        if isinstance(scene, TopologyScene):
            scene.drag_finished()

    def mouseDoubleClickEvent(self, event) -> None:
        scene = self.scene()
        if isinstance(scene, TopologyScene):
            scene.edit_requested.emit(self.device.node_id)
        event.accept()

    def hoverEnterEvent(self, e) -> None:
        self._hovered = True
        self.update()
        super().hoverEnterEvent(e)

    def hoverLeaveEvent(self, e) -> None:
        self._hovered = False
        self.update()
        super().hoverLeaveEvent(e)


class EdgeItem(QGraphicsPathItem):
    """Связь: ломаная из раскладки или прямая после ручного перемещения."""

    def __init__(self, scene: "TopologyScene", src: str, dst: str) -> None:
        super().__init__()
        self._scene = scene
        self.src = src
        self.dst = dst
        self._hovered = False
        self.setZValue(0)
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.setAcceptHoverEvents(True)
        self.update_path()

    @property
    def kind(self) -> str:
        g = self._scene.topology.graph
        return g.edges[self.src, self.dst].get("label", "") \
            if g.has_edge(self.src, self.dst) else ""

    def update_path(self) -> None:
        pts = self._scene.topology.edge_route(self.src, self.dst)
        path = QPainterPath()
        if len(pts) >= 2:
            path.moveTo(*pts[0])
            for x, y in pts[1:]:
                path.lineTo(x, y)
        self.setPath(path)
        self._restyle()

    def _restyle(self) -> None:
        st = link_style(self.kind)
        width = st.width + (1.5 if (self._hovered or self.isSelected()) else 0)
        color = QColor("#e74c3c") if self.isSelected() else QColor(st.color)
        pen = QPen(color, width)
        pen.setJoinStyle(Qt.RoundJoin)
        pen.setCapStyle(Qt.RoundCap)
        if st.dash:
            pen.setDashPattern([d / max(st.width, 1) for d in st.dash])
        self.setPen(pen)
        data = self._scene.topology.graph.edges[self.src, self.dst] \
            if self._scene.topology.graph.has_edge(self.src, self.dst) else {}
        tip = link_label(self.kind)
        ports = " ↔ ".join(p for p in (data.get("local_port"),
                                        data.get("remote_port")) if p)
        a = self._scene.topology.devices.get(self.src)
        b = self._scene.topology.devices.get(self.dst)
        if a and b:
            tip += f"\n{a.display_name()} — {b.display_name()}"
        if ports:
            tip += f"\n{ports}"
        self.setToolTip(tip + "\nCtrl+клик — удалить")

    def shape(self) -> QPainterPath:
        stroker = QPainterPathStroker()
        stroker.setWidth(10)
        return stroker.createStroke(self.path())

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemSelectedHasChanged:
            self._restyle()
        return super().itemChange(change, value)

    def hoverEnterEvent(self, event) -> None:
        self._hovered = True
        self._restyle()
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event) -> None:
        self._hovered = False
        self._restyle()
        super().hoverLeaveEvent(event)

    def mousePressEvent(self, event) -> None:
        if event.modifiers() & Qt.ControlModifier:
            self._scene.delete_edge(self.src, self.dst)
            event.accept()
            return
        super().mousePressEvent(event)


# ═══════════════════════════════════════════════════════════════════════════
# Сцена
# ═══════════════════════════════════════════════════════════════════════════

class TopologyScene(QGraphicsScene):
    topology_changed = pyqtSignal()
    edit_requested = pyqtSignal(str)
    link_mode_finished = pyqtSignal()

    def __init__(self, topology: NetworkTopology,
                 visible_types: set[str] | None = None, parent=None) -> None:
        super().__init__(parent)
        self.topology = topology
        self.visible_types: set[str] = (set(DEVICE_TYPES) if visible_types
                                        is None else set(visible_types))
        self.nodes: dict[str, NodeItem] = {}
        self.edges: list[EdgeItem] = []
        self.zones: dict[str, SubnetZone] = {}
        self._highlight: set[str] | None = None
        self._link_mode = False
        self._link_src: Optional[str] = None
        self._zone_timer = QTimer()
        self._zone_timer.setSingleShot(True)
        self._zone_timer.setInterval(30)
        self._zone_timer.timeout.connect(self._update_zones)
        self.setBackgroundBrush(QColor("#f4f6f7"))
        self.rebuild()

    # ── Построение ──

    def rebuild(self) -> None:
        self.clear()
        self.nodes.clear()
        self.edges.clear()
        self.zones.clear()
        self.topology.reindex()
        self.topology.place_missing()
        for cidr, nids in zone_members(self.topology).items():
            zone = SubnetZone(cidr)
            zone.node_ids = nids
            self.addItem(zone)
            self.zones[cidr] = zone
        for nid, dev in self.topology.devices.items():
            item = NodeItem(dev)
            self.addItem(item)
            self.nodes[nid] = item
        for src, dst, _attrs in self.topology.links:
            self._add_edge_item(src, dst)
        self.apply_filter(self.visible_types)
        self._update_scene_rect()

    def _add_edge_item(self, src: str, dst: str) -> Optional[EdgeItem]:
        if src not in self.nodes or dst not in self.nodes:
            return None
        edge = EdgeItem(self, src, dst)
        self.addItem(edge)
        self.edges.append(edge)
        edge.setVisible(self.nodes[src].isVisible()
                        and self.nodes[dst].isVisible())
        return edge

    def _update_zones(self) -> None:
        for zone in self.zones.values():
            zone.update_geometry(self.nodes)

    def _update_scene_rect(self) -> None:
        self._update_zones()
        rect = self.itemsBoundingRect().adjusted(-200, -200, 200, 200)
        self.setSceneRect(rect)

    # ── Фильтр и подсветка ──

    def apply_filter(self, visible_types: set[str]) -> None:
        self.visible_types = set(visible_types)
        for nid, item in self.nodes.items():
            item.setVisible(item.device.device_type in self.visible_types)
        for edge in self.edges:
            edge.setVisible(self.nodes[edge.src].isVisible()
                            and self.nodes[edge.dst].isVisible())
        self._update_zones()

    def set_highlight(self, node_ids: set[str] | None) -> None:
        """None — снять подсветку; иначе подсветить найденные, остальные приглушить."""
        self._highlight = node_ids
        for nid, item in self.nodes.items():
            if node_ids is None:
                item.set_state(False, False)
            else:
                item.set_state(nid in node_ids, nid not in node_ids)
        for edge in self.edges:
            edge.setOpacity(0.25 if node_ids is not None else 1.0)

    # ── Перемещение ──

    def node_moved(self, item: NodeItem) -> None:
        nid = item.device.node_id
        for edge in self.edges:
            if edge.src == nid or edge.dst == nid:
                edge.update_path()
        self._zone_timer.start()

    def drag_finished(self) -> None:
        self._update_scene_rect()
        self.topology_changed.emit()

    def move_subnet(self, subnet: str, delta: QPointF) -> None:
        moved = {nid for nid, it in self.nodes.items()
                 if it.device.subnet == subnet and subnet}
        if not moved:
            return
        for nid in moved:
            self.nodes[nid].moveBy(delta.x(), delta.y())
        # Маршруты внутри подсети сдвигаем вместе с узлами — они остаются ломаными
        g = self.topology.graph
        for u, v, data in g.edges(data=True):
            if u in moved and v in moved and data.get("points"):
                data["points"] = [[x + delta.x(), y + delta.y()]
                                  for x, y in data["points"]]
                if data.get("route_at"):
                    data["route_at"] = [[x + delta.x(), y + delta.y()]
                                        for x, y in data["route_at"]]
        for edge in self.edges:
            if edge.src in moved or edge.dst in moved:
                edge.update_path()
        self._zone_timer.start()

    # ── Правка ──

    def add_device(self, device: Device) -> None:
        self.topology.add_device(device)
        self.rebuild()
        self.topology_changed.emit()

    def delete_device(self, node_id: str) -> None:
        self.topology.remove_device(node_id)
        self.rebuild()
        self.topology_changed.emit()

    def delete_edge(self, src: str, dst: str) -> None:
        self.topology.remove_link(src, dst)
        for edge in [e for e in self.edges
                     if {e.src, e.dst} == {src, dst}]:
            self.removeItem(edge)
            self.edges.remove(edge)
        self.topology_changed.emit()

    def delete_selected(self) -> int:
        edges = [e for e in self.selectedItems() if isinstance(e, EdgeItem)]
        nodes = [n for n in self.selectedItems() if isinstance(n, NodeItem)]
        for e in edges:
            self.topology.remove_link(e.src, e.dst)
        for n in nodes:
            self.topology.remove_device(n.device.node_id)
        if edges or nodes:
            self.rebuild()
            self.topology_changed.emit()
        return len(edges) + len(nodes)

    def add_link_between(self, src: str, dst: str, label: str = "manual") -> None:
        self.topology.add_link(src, dst, label)
        self.topology.clear_route(src, dst)
        if not any({e.src, e.dst} == {src, dst} for e in self.edges):
            self._add_edge_item(src, dst)
        else:
            for e in self.edges:
                if {e.src, e.dst} == {src, dst}:
                    e.update_path()
        self.topology_changed.emit()

    def merge_nodes(self, primary_id: str, secondary_id: str) -> None:
        if self.topology.merge_devices(primary_id, secondary_id):
            self.rebuild()
            self.topology_changed.emit()

    def split_node(self, node_id: str, split_ip: str) -> None:
        new_id = self.topology.split_device(node_id, split_ip)
        if new_id:
            base = self.topology.devices[node_id].position or (0, 0)
            self.topology.devices[new_id].position = (base[0] + NODE_W + 40,
                                                      base[1])
            self.rebuild()
            self.topology_changed.emit()

    def relayout(self, mode: str) -> None:
        self.topology.apply_layout(mode)
        self.rebuild()
        self.topology_changed.emit()

    # ── Режим связи ──

    def start_link_mode(self, src: Optional[str] = None) -> None:
        self._link_mode = True
        self._link_src = src

    def stop_link_mode(self) -> None:
        self._link_mode = False
        self._link_src = None
        self.link_mode_finished.emit()

    def node_at(self, pos: QPointF) -> Optional[NodeItem]:
        return next((i for i in self.items(pos)
                     if isinstance(i, NodeItem) and i.isVisible()), None)

    def mousePressEvent(self, event) -> None:
        if self._link_mode and event.button() == Qt.LeftButton:
            node = self.node_at(event.scenePos())
            if node:
                nid = node.device.node_id
                if self._link_src is None:
                    self._link_src = nid
                    node.setSelected(True)
                else:
                    if self._link_src != nid:
                        self.add_link_between(self._link_src, nid)
                    self.stop_link_mode()
            else:
                self.stop_link_mode()
            event.accept()
            return
        super().mousePressEvent(event)

    # ── Контекстное меню ──

    def contextMenuEvent(self, event) -> None:
        items = self.items(event.scenePos())
        node = next((i for i in items if isinstance(i, NodeItem)), None)
        edge = next((i for i in items if isinstance(i, EdgeItem)), None)
        menu = QMenu()
        if node:
            dev = node.device
            menu.addSection(f"{'★ ' if dev.is_multihomed else ''}"
                            f"{dev.display_name()}  [{dev.type_label}]")
            edit_a = menu.addAction("Редактировать…")
            link_a = menu.addAction("Добавить связь отсюда")
            merge_a = menu.addAction("Объединить с узлом…")
            split_a = menu.addAction("Отделить интерфейс…")
            split_a.setEnabled(len(dev.interfaces) > 1)
            menu.addSeparator()
            del_a = menu.addAction("Удалить устройство")
            action = menu.exec_(event.screenPos())
            if action == edit_a:
                self.edit_requested.emit(dev.node_id)
            elif action == del_a:
                if QMessageBox.question(
                        None, "Удалить?", f"Удалить {dev.display_name()}?",
                        QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
                    self.delete_device(dev.node_id)
            elif action == link_a:
                self.start_link_mode(dev.node_id)
            elif action == merge_a:
                d = MergeDialog(dev, self.topology)
                if d.exec_() == QDialog.Accepted and d.selected_id:
                    self.merge_nodes(dev.node_id, d.selected_id)
            elif action == split_a:
                d = SplitDialog(dev)
                if d.exec_() == QDialog.Accepted and d.selected_ip:
                    self.split_node(dev.node_id, d.selected_ip)
        elif edge:
            menu.addSection(link_label(edge.kind))
            del_e = menu.addAction("Удалить связь")
            if menu.exec_(event.screenPos()) == del_e:
                self.delete_edge(edge.src, edge.dst)
        else:
            add_a = menu.addAction("Добавить устройство здесь…")
            if menu.exec_(event.screenPos()) == add_a:
                dev = Device(ip="0.0.0.0")
                if DeviceEditDialog(dev).exec_() == QDialog.Accepted:
                    dev.position = (event.scenePos().x(), event.scenePos().y())
                    self.add_device(dev)


# ═══════════════════════════════════════════════════════════════════════════
# Вид (масштаб и панорама)
# ═══════════════════════════════════════════════════════════════════════════

class TopologyView(QGraphicsView):
    zoom_changed = pyqtSignal(float)

    def __init__(self) -> None:
        super().__init__()
        self.setRenderHints(QPainter.Antialiasing | QPainter.TextAntialiasing
                            | QPainter.SmoothPixmapTransform)
        self.setDragMode(QGraphicsView.RubberBandDrag)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.AnchorViewCenter)
        self.setViewportUpdateMode(QGraphicsView.SmartViewportUpdate)
        self.setAcceptDrops(False)
        self._panning = False
        self._pan_start = QPointF()

    def zoom_by(self, factor: float) -> None:
        current = self.transform().m11()
        target = min(max(current * factor, 0.05), 6.0)
        factor = target / current
        self.scale(factor, factor)
        self.zoom_changed.emit(target)

    def fit_all(self) -> None:
        scene = self.scene()
        if not scene:
            return
        rect = scene.itemsBoundingRect()
        if rect.isEmpty():
            return
        self.fitInView(rect.adjusted(-40, -40, 40, 40), Qt.KeepAspectRatio)
        if self.transform().m11() > 1.5:
            self.resetTransform()
            self.scale(1.5, 1.5)
            self.centerOn(rect.center())
        self.zoom_changed.emit(self.transform().m11())

    def reset_zoom(self) -> None:
        self.resetTransform()
        self.zoom_changed.emit(1.0)

    def wheelEvent(self, event) -> None:
        if event.modifiers() & Qt.ShiftModifier:
            super().wheelEvent(event)       # Shift+колесо — прокрутка
            return
        steps = event.angleDelta().y() / 120
        if steps:
            self.zoom_by(1.15 ** steps)
        event.accept()

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MiddleButton:
            self._panning = True
            self._pan_start = event.pos()
            self.setCursor(Qt.ClosedHandCursor)
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:
        if self._panning:
            d = event.pos() - self._pan_start
            self._pan_start = event.pos()
            self.horizontalScrollBar().setValue(
                self.horizontalScrollBar().value() - d.x())
            self.verticalScrollBar().setValue(
                self.verticalScrollBar().value() - d.y())
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.MiddleButton and self._panning:
            self._panning = False
            self.unsetCursor()
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key_Space and not event.isAutoRepeat():
            self.setDragMode(QGraphicsView.ScrollHandDrag)
            return
        super().keyPressEvent(event)

    def keyReleaseEvent(self, event) -> None:
        if event.key() == Qt.Key_Space and not event.isAutoRepeat():
            self.setDragMode(QGraphicsView.RubberBandDrag)
            return
        super().keyReleaseEvent(event)


# ═══════════════════════════════════════════════════════════════════════════
# Диалоги
# ═══════════════════════════════════════════════════════════════════════════

class DeviceEditDialog(QDialog):
    def __init__(self, device: Device, topology: NetworkTopology | None = None,
                 parent=None) -> None:
        super().__init__(parent)
        self.device = device
        self.setWindowTitle("Свойства устройства")
        self.setMinimumWidth(440)
        layout = QFormLayout(self)

        self.ip_edit = QLineEdit(device.ip)
        self.hostname_edit = QLineEdit(device.hostname or "")
        self.mac_edit = QLineEdit(device.mac or "")
        self.vendor_edit = QLineEdit(device.vendor or "")
        self.os_edit = QLineEdit(device.os_name or "")
        self.model_edit = QLineEdit(device.model or "")
        self.subnet_edit = QLineEdit(device.subnet or "")
        self.location_edit = QLineEdit(device.location or "")
        self.notes_edit = QLineEdit(device.notes)
        self.gateway_cb = QCheckBox("Шлюз подсети")
        self.gateway_cb.setChecked(device.is_gateway)

        self.type_combo = QComboBox()
        for t in DEVICE_TYPES:
            self.type_combo.addItem(type_icon(t, 18),
                                    DEVICE_TYPE_LABELS.get(t, t), t)
        self.type_combo.setCurrentIndex(
            DEVICE_TYPES.index(device.device_type)
            if device.device_type in DEVICE_TYPES else 0)

        layout.addRow("IP-адрес:", self.ip_edit)
        layout.addRow("Имя хоста:", self.hostname_edit)
        layout.addRow("Тип:", self.type_combo)
        layout.addRow("MAC-адрес:", self.mac_edit)
        layout.addRow("Производитель:", self.vendor_edit)
        layout.addRow("ОС:", self.os_edit)
        layout.addRow("Модель:", self.model_edit)
        layout.addRow("Подсеть (CIDR):", self.subnet_edit)
        layout.addRow("Расположение:", self.location_edit)
        layout.addRow("Заметки:", self.notes_edit)
        layout.addRow("", self.gateway_cb)
        if len(device.interfaces) > 1:
            ta = QPlainTextEdit(device.interfaces_label())
            ta.setReadOnly(True)
            ta.setMaximumHeight(90)
            layout.addRow("Все IP:", ta)

        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self._apply)
        bb.rejected.connect(self.reject)
        layout.addRow(bb)

    def _apply(self) -> None:
        import ipaddress
        ip = self.ip_edit.text().strip()
        subnet = self.subnet_edit.text().strip()
        try:
            ipaddress.ip_address(ip)
            if subnet:
                subnet = str(ipaddress.ip_network(subnet, strict=False))
        except ValueError as exc:
            QMessageBox.warning(self, "Некорректное значение", str(exc))
            return
        d = self.device
        old_ip = d.ip
        d.ip = ip
        for iface in d.interfaces:
            if iface.ip == old_ip:
                iface.ip = ip
                iface.subnet = iface.subnet or subnet
        if not d.interfaces:
            d.add_interface(ip, subnet)
        d.hostname = self.hostname_edit.text().strip() or None
        d.mac = self.mac_edit.text().strip() or None
        d.vendor = self.vendor_edit.text().strip() or None
        d.os_name = self.os_edit.text().strip()
        d.model = self.model_edit.text().strip()
        d.subnet = subnet
        d.location = self.location_edit.text().strip()
        d.notes = self.notes_edit.text().strip()
        d.is_gateway = self.gateway_cb.isChecked()
        new_type = self.type_combo.currentData()
        if new_type != d.device_type:
            d.device_type = new_type
            d.confidence = 100
            d.evidence = ["Тип задан вручную"] + d.evidence
        self.accept()


class MergeDialog(QDialog):
    def __init__(self, device: Device, topology: NetworkTopology,
                 parent=None) -> None:
        super().__init__(parent)
        self.selected_id: Optional[str] = None
        self.setWindowTitle(f"Объединить {device.display_name()} с…")
        self.setMinimumWidth(380)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Выберите узел — его интерфейсы и связи "
                                "перейдут к текущему:"))
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Фильтр…")
        layout.addWidget(self.filter)
        self.lw = QListWidget()
        others = sorted((d for nid, d in topology.devices.items()
                         if nid != device.node_id and not d.is_virtual),
                        key=lambda d: ip_sort_key(d.ip))
        for dev in others:
            item = QListWidgetItem(type_icon(dev.device_type, 18),
                                   f"{dev.ip}   {dev.display_name()}   "
                                   f"[{dev.type_label}]")
            item.setData(Qt.UserRole, dev.node_id)
            self.lw.addItem(item)
        self.lw.itemDoubleClicked.connect(lambda _i: self._apply())
        self.filter.textChanged.connect(self._filter)
        layout.addWidget(self.lw)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self._apply)
        bb.rejected.connect(self.reject)
        layout.addWidget(bb)

    def _filter(self, text: str) -> None:
        t = text.lower()
        for i in range(self.lw.count()):
            it = self.lw.item(i)
            it.setHidden(bool(t) and t not in it.text().lower())

    def _apply(self) -> None:
        it = self.lw.currentItem()
        if it:
            self.selected_id = it.data(Qt.UserRole)
            self.accept()


class SplitDialog(QDialog):
    def __init__(self, device: Device, parent=None) -> None:
        super().__init__(parent)
        self.selected_ip: Optional[str] = None
        self.setWindowTitle(f"Разделить {device.display_name()}")
        self.setMinimumWidth(320)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Выберите IP для отделения в новый узел:"))
        self.lw = QListWidget()
        for iface in device.interfaces:
            if iface.ip == device.ip:
                continue
            lbl = iface.ip
            if iface.subnet:
                lbl += f"  [{iface.subnet}]"
            if iface.iface_name:
                lbl += f"  ({iface.iface_name})"
            item = QListWidgetItem(lbl)
            item.setData(Qt.UserRole, iface.ip)
            self.lw.addItem(item)
        layout.addWidget(self.lw)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self._apply)
        bb.rejected.connect(self.reject)
        layout.addWidget(bb)

    def _apply(self) -> None:
        it = self.lw.currentItem()
        if it:
            self.selected_ip = it.data(Qt.UserRole)
            self.accept()


# ═══════════════════════════════════════════════════════════════════════════
# Главное окно
# ═══════════════════════════════════════════════════════════════════════════

ROLE_ID = Qt.UserRole + 1

QT_EXPORTS = {
    ".pdf": "Векторный PDF (*.pdf)",
    ".png": "Изображение PNG, 2× (*.png)",
}


class MainWindow(QMainWindow):
    def __init__(self, topology: NetworkTopology) -> None:
        super().__init__()
        self.topology = topology
        self._current_file: Optional[str] = None
        self._modified = False
        self._worker: Optional[ScanWorker] = None
        self._scene: Optional[TopologyScene] = None
        self._syncing = False
        self.settings = QSettings(ORG_NAME, SETTINGS_APP)

        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(type_icon("router", 64))
        self.resize(1440, 880)
        self.setAcceptDrops(True)
        self.setDockOptions(QMainWindow.AnimatedDocks
                            | QMainWindow.AllowTabbedDocks)

        self._log_handler = QtLogHandler()
        logging.getLogger().addHandler(self._log_handler)

        self.view = TopologyView()
        self.setCentralWidget(self.view)
        self._build_actions()
        self._build_docks()
        self._build_toolbar()
        self._build_menu()
        self._build_statusbar()
        self._log_handler.bridge.message.connect(self._append_log)
        self._restore_settings()
        self._refresh_scene(fit=True)

    # ── Действия ─────────────────────────────────────────────────────────────

    def _act(self, text: str, slot, shortcut=None, icon=None,
             tip: str = "") -> QAction:
        a = QAction(text, self)
        if shortcut:
            a.setShortcut(QKeySequence(shortcut))
        if icon is not None:
            a.setIcon(icon if isinstance(icon, QIcon)
                      else self.style().standardIcon(icon))
        if tip:
            a.setToolTip(tip + (f" ({a.shortcut().toString()})"
                                if shortcut else ""))
        a.triggered.connect(slot)
        return a

    def _build_actions(self) -> None:
        S = QStyle
        self.a_open = self._act("Открыть…", self._open_file, QKeySequence.Open,
                                S.SP_DialogOpenButton, "Открыть проект")
        self.a_save = self._act("Сохранить", self._save_file, QKeySequence.Save,
                                S.SP_DialogSaveButton, "Сохранить проект")
        self.a_save_as = self._act("Сохранить как…", self._save_as,
                                   "Ctrl+Shift+S")
        self.a_fit = self._act("Вписать", self.view.fit_all, "F",
                               S.SP_TitleBarMaxButton, "Вписать схему в окно")
        self.a_zoom_in = self._act("Увеличить", lambda: self.view.zoom_by(1.25),
                                   QKeySequence.ZoomIn, S.SP_ArrowUp,
                                   "Увеличить")
        self.a_zoom_out = self._act("Уменьшить",
                                    lambda: self.view.zoom_by(0.8),
                                    QKeySequence.ZoomOut, S.SP_ArrowDown,
                                    "Уменьшить")
        self.a_zoom_reset = self._act("Масштаб 100%", self.view.reset_zoom,
                                      "Ctrl+0")
        self.a_relayout = self._act("Перестроить", self._relayout, "Ctrl+L",
                                    S.SP_BrowserReload,
                                    "Заново разложить схему")
        self.a_link = self._act("Связь", self._toggle_link_mode, "Ctrl+K",
                                type_icon("switch", 24),
                                "Режим связи: клик по двум узлам")
        self.a_link.setCheckable(True)
        self.a_delete = self._act("Удалить выбранное", self._delete_selected,
                                  QKeySequence.Delete)
        self.a_add = self._act("Добавить устройство…", self._add_device_dialog,
                               "Ctrl+N")
        self.a_find = self._act("Поиск", self._focus_search, QKeySequence.Find)
        for a in (self.a_find, self.a_delete):
            self.addAction(a)

    # ── Панели ───────────────────────────────────────────────────────────────

    def _build_docks(self) -> None:
        # Сканирование
        scan = QWidget()
        form = QFormLayout(scan)
        form.setContentsMargins(8, 8, 8, 8)
        self.subnets_edit = QLineEdit()
        self.subnets_edit.setPlaceholderText("192.168.1.0/24, 10.0.0.0/24")
        self.subnets_edit.setToolTip("Подсети через запятую или пробел")
        self.subnets_edit.returnPressed.connect(self._on_scan)
        auto_btn = QToolButton()
        auto_btn.setText("Моя")
        auto_btn.setToolTip("Подставить подсеть этого компьютера")
        auto_btn.clicked.connect(self._fill_local_subnet)
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(self.subnets_edit)
        row.addWidget(auto_btn)
        row_w = QWidget()
        row_w.setLayout(row)
        self.community_edit = QLineEdit("public")
        self.community_edit.setToolTip("SNMP community")
        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(0.2, 10.0)
        self.timeout_spin.setSingleStep(0.5)
        self.timeout_spin.setValue(1.0)
        self.timeout_spin.setSuffix(" с")
        self.max_hosts_spin = QSpinBox()
        self.max_hosts_spin.setRange(1, 65534)
        self.max_hosts_spin.setValue(254)
        self.parallel_cb = QCheckBox("Подсети параллельно")
        self.scan_btn = QPushButton("▶  Сканировать")
        self.scan_btn.setDefault(True)
        self.scan_btn.clicked.connect(self._on_scan)
        self.stop_btn = QPushButton("■  Стоп")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setToolTip("Остановить после текущей подсети")
        self.stop_btn.clicked.connect(self._on_stop)
        btns = QHBoxLayout()
        btns.addWidget(self.scan_btn)
        btns.addWidget(self.stop_btn)
        btn_w = QWidget()
        btn_w.setLayout(btns)
        self.progress = QProgressBar()
        self.progress.setTextVisible(True)
        self.progress.setValue(0)
        self.progress_label = QLabel("")
        self.progress_label.setWordWrap(True)
        form.addRow("Подсети:", row_w)
        form.addRow("Community:", self.community_edit)
        form.addRow("Таймаут:", self.timeout_spin)
        form.addRow("Макс. хостов:", self.max_hosts_spin)
        form.addRow("", self.parallel_cb)
        form.addRow(btn_w)
        form.addRow(self.progress)
        form.addRow(self.progress_label)
        self.dock_scan = self._dock("Сканирование", "dock_scan", scan,
                                    Qt.LeftDockWidgetArea)

        # Устройства
        dev_w = QWidget()
        v = QVBoxLayout(dev_w)
        v.setContentsMargins(4, 4, 4, 4)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Устройство", "IP", "Тип", "Производитель",
                                   "ОС"])
        self.tree.setRootIsDecorated(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.tree.setSortingEnabled(False)
        self.tree.header().setSectionResizeMode(QHeaderView.Interactive)
        self.tree.header().setStretchLastSection(True)
        self.tree.setIconSize(QSize(18, 18))
        self.tree.itemSelectionChanged.connect(self._tree_selection_changed)
        self.tree.itemDoubleClicked.connect(self._tree_double_clicked)
        v.addWidget(self.tree)
        self.dock_devices = self._dock("Устройства", "dock_devices", dev_w,
                                       Qt.LeftDockWidgetArea)
        self.tabifyDockWidget(self.dock_scan, self.dock_devices)
        self.dock_scan.raise_()

        # Свойства
        prop = QWidget()
        pv = QVBoxLayout(prop)
        pv.setContentsMargins(4, 4, 4, 4)
        self.props = QTextBrowser()
        self.props.setOpenLinks(False)
        self.edit_btn = QPushButton("Редактировать…")
        self.edit_btn.setEnabled(False)
        self.edit_btn.clicked.connect(self._edit_selected)
        pv.addWidget(self.props)
        pv.addWidget(self.edit_btn)
        self.dock_props = self._dock("Свойства", "dock_props", prop,
                                     Qt.RightDockWidgetArea)

        # Журнал
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(3000)
        f = QFont("Consolas")
        f.setStyleHint(QFont.Monospace)
        f.setPointSizeF(8.5)
        self.log_view.setFont(f)
        self.dock_log = self._dock("Журнал", "dock_log", self.log_view,
                                   Qt.BottomDockWidgetArea)
        self.dock_log.hide()

    def _dock(self, title: str, name: str, widget: QWidget, area) -> QDockWidget:
        d = QDockWidget(title, self)
        d.setObjectName(name)
        d.setWidget(widget)
        self.addDockWidget(area, d)
        return d

    def _build_toolbar(self) -> None:
        tb = self.addToolBar("Основная")
        tb.setObjectName("toolbar_main")
        tb.setIconSize(QSize(20, 20))
        tb.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        tb.addAction(self.a_open)
        tb.addAction(self.a_save)

        self.export_btn = QToolButton()
        self.export_btn.setText("Экспорт")
        self.export_btn.setIcon(self.style().standardIcon(
            QStyle.SP_DialogSaveButton))
        self.export_btn.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.export_btn.setPopupMode(QToolButton.InstantPopup)
        self.export_menu = self._make_export_menu()
        self.export_btn.setMenu(self.export_menu)
        tb.addWidget(self.export_btn)
        tb.addSeparator()

        tb.addWidget(QLabel(" Раскладка: "))
        self.layout_combo = QComboBox()
        for key, title in LAYOUT_MODES.items():
            self.layout_combo.addItem(title, key)
        self.layout_combo.activated.connect(lambda _i: self._relayout())
        tb.addWidget(self.layout_combo)
        tb.addAction(self.a_relayout)
        tb.addSeparator()
        tb.addAction(self.a_fit)
        tb.addAction(self.a_zoom_in)
        tb.addAction(self.a_zoom_out)
        tb.addSeparator()
        tb.addAction(self.a_link)

        self.filter_btn = QToolButton()
        self.filter_btn.setText("Типы")
        self.filter_btn.setIcon(self.style().standardIcon(
            QStyle.SP_FileDialogListView))
        self.filter_btn.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.filter_btn.setPopupMode(QToolButton.InstantPopup)
        self.filter_btn.setToolTip("Показать / скрыть типы устройств")
        self.filter_menu = QMenu(self)
        self.type_actions: dict[str, QAction] = {}
        self.filter_menu.addAction("Показать все", lambda: self._set_all_types(True))
        self.filter_menu.addAction("Скрыть все", lambda: self._set_all_types(False))
        for group, types in DEVICE_TYPE_GROUPS.items():
            self.filter_menu.addSection(group)
            for t in types:
                a = QAction(type_icon(t, 18), DEVICE_TYPE_LABELS[t], self)
                a.setCheckable(True)
                a.setChecked(True)
                a.toggled.connect(self._on_filter_changed)
                self.filter_menu.addAction(a)
                self.type_actions[t] = a
        self.filter_btn.setMenu(self.filter_menu)
        tb.addWidget(self.filter_btn)
        tb.addSeparator()

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Поиск: имя, IP, MAC, вендор, ОС  (Ctrl+F)")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.setMinimumWidth(260)
        self.search_edit.textChanged.connect(self._on_search)
        self.search_edit.returnPressed.connect(self._search_next)
        tb.addWidget(self.search_edit)
        self._search_hits: list[str] = []
        self._search_pos = -1

    def _make_export_menu(self) -> QMenu:
        menu = QMenu("Экспорт", self)
        for ext, title in list(EXPORT_FORMATS.items()) + list(QT_EXPORTS.items()):
            if ext == ".json":
                continue
            # triggered(bool) передаёт checked первым аргументом
            menu.addAction(title.split(" (")[0],
                           lambda _checked=False, e=ext: self._export(e))
        return menu

    def _build_menu(self) -> None:
        mb = self.menuBar()
        fm = mb.addMenu("&Файл")
        fm.addAction(self.a_open)
        fm.addAction(self.a_save)
        fm.addAction(self.a_save_as)
        fm.addSeparator()
        fm.addMenu(self._make_export_menu())
        fm.addSeparator()
        fm.addAction("Выход", self.close, QKeySequence.Quit)

        em = mb.addMenu("&Правка")
        em.addAction(self.a_add)
        em.addAction(self.a_link)
        em.addAction(self.a_delete)
        em.addSeparator()
        em.addAction("Объединить по MAC (авто)", self._auto_merge)
        em.addSeparator()
        em.addAction("Обновить OUI-базу производителей…", self._update_oui_db)

        vm = mb.addMenu("&Вид")
        vm.addAction(self.a_fit)
        vm.addAction(self.a_zoom_reset)
        vm.addAction(self.a_zoom_in)
        vm.addAction(self.a_zoom_out)
        vm.addSeparator()
        group = QActionGroup(self)
        self.layout_actions: dict[str, QAction] = {}
        for key, title in LAYOUT_MODES.items():
            a = QAction(title, self, checkable=True)
            a.triggered.connect(lambda _c, k=key: self._set_layout(k))
            group.addAction(a)
            vm.addAction(a)
            self.layout_actions[key] = a
        vm.addAction(self.a_relayout)
        vm.addSeparator()
        for d in (self.dock_scan, self.dock_devices, self.dock_props,
                  self.dock_log):
            vm.addAction(d.toggleViewAction())

        hm = mb.addMenu("&Справка")
        hm.addAction("Обозначения", self._show_legend)
        hm.addAction("Управление", self._show_help, QKeySequence.HelpContents)
        hm.addAction("О программе", self._show_about)

    def _build_statusbar(self) -> None:
        self.status_counts = QLabel()
        self.status_zoom = QLabel()
        self.statusBar().addPermanentWidget(self.status_counts)
        self.statusBar().addPermanentWidget(self.status_zoom)
        self.view.zoom_changed.connect(
            lambda z: self.status_zoom.setText(f"  {z * 100:.0f}%  "))

    # ── Настройки ────────────────────────────────────────────────────────────

    def _restore_settings(self) -> None:
        s = self.settings
        geo = s.value("geometry")
        if geo is not None:
            self.restoreGeometry(geo)
        state = s.value("state")
        if state is not None:
            self.restoreState(state)
        self.subnets_edit.setText(s.value("subnets", "", str))
        self.community_edit.setText(s.value("community", "public", str))
        self.parallel_cb.setChecked(s.value("parallel", False, bool))
        try:
            self.timeout_spin.setValue(float(s.value("timeout", 1.0)))
            self.max_hosts_spin.setValue(int(s.value("max_hosts", 254)))
        except (TypeError, ValueError):
            pass
        mode = self.topology.layout_mode if self.topology.devices else \
            s.value("layout", "tree", str)
        self._select_layout_ui(mode)
        self.topology.layout_mode = mode

    def _save_settings(self) -> None:
        s = self.settings
        s.setValue("geometry", self.saveGeometry())
        s.setValue("state", self.saveState())
        s.setValue("subnets", self.subnets_edit.text())
        s.setValue("community", self.community_edit.text())
        s.setValue("parallel", self.parallel_cb.isChecked())
        s.setValue("timeout", self.timeout_spin.value())
        s.setValue("max_hosts", self.max_hosts_spin.value())
        s.setValue("layout", self._layout_mode())

    def _last_dir(self) -> str:
        return self.settings.value("last_dir", os.path.expanduser("~"), str)

    def _remember_dir(self, path: str) -> None:
        self.settings.setValue("last_dir", os.path.dirname(os.path.abspath(path)))

    # ── Сцена ────────────────────────────────────────────────────────────────

    def _visible_types(self) -> set[str]:
        return {t for t, a in self.type_actions.items() if a.isChecked()}

    def _refresh_scene(self, fit: bool = False) -> None:
        old = self._scene
        scene = TopologyScene(self.topology, self._visible_types(), self)
        scene.topology_changed.connect(self._on_changed)
        scene.edit_requested.connect(self._edit_device)
        scene.selectionChanged.connect(self._scene_selection_changed)
        scene.link_mode_finished.connect(lambda: self.a_link.setChecked(False))
        self.view.setScene(scene)
        self._scene = scene
        if old is not None:
            old.deleteLater()
        self._populate_tree()
        self._update_props()
        self._update_status()
        if self.search_edit.text():
            self._on_search(self.search_edit.text())
        if fit:
            QTimer.singleShot(0, self.view.fit_all)

    def _on_changed(self) -> None:
        self._modified = True
        self._populate_tree()
        self._update_props()
        self._update_status()

    def _update_title(self) -> None:
        name = os.path.basename(self._current_file) if self._current_file \
            else "без имени"
        self.setWindowTitle(f"{name}{' *' if self._modified else ''} — "
                            f"{APP_NAME}")

    def _update_status(self) -> None:
        devs = [d for d in self.topology.devices.values() if not d.is_virtual]
        multi = sum(1 for d in devs if d.is_multihomed)
        subnets = len({d.subnet for d in devs if d.subnet})
        hidden = len(set(DEVICE_TYPES) - self._visible_types())
        text = (f"Устройств: {len(devs)}  ·  подсетей: {subnets}  ·  "
                f"связей: {len(self.topology.links)}  ·  мульти: {multi}")
        if hidden:
            text += f"  ·  скрыто типов: {hidden}"
        self.status_counts.setText(text + "  ")
        self._update_title()

    # ── Дерево устройств и свойства ──────────────────────────────────────────

    def _populate_tree(self) -> None:
        self._syncing = True
        self.tree.clear()
        groups: dict[str, list[Device]] = {}
        for dev in self.topology.devices.values():
            groups.setdefault(dev.subnet or "Без подсети", []).append(dev)

        def gkey(name: str):
            return (name == "Без подсети", ip_sort_key(name.split("/")[0]))
        for name in sorted(groups, key=gkey):
            devs = sorted(groups[name], key=lambda d: (not d.is_gateway,
                                                       d.is_virtual,
                                                       ip_sort_key(d.ip)))
            top = QTreeWidgetItem([f"{name}  ({len(devs)})"])
            f = top.font(0)
            f.setBold(True)
            top.setFont(0, f)
            top.setFlags(top.flags() & ~Qt.ItemIsSelectable)
            self.tree.addTopLevelItem(top)
            for d in devs:
                it = QTreeWidgetItem([
                    d.display_name(), "" if d.is_virtual else d.ip,
                    d.type_label, d.vendor or "", d.os_name or ""])
                it.setIcon(0, type_icon(d.device_type, 18))
                it.setData(0, ROLE_ID, d.node_id)
                it.setToolTip(0, device_tooltip(d))
                top.addChild(it)
            top.setExpanded(True)
        for col, w in enumerate((190, 110, 120, 140)):
            self.tree.setColumnWidth(col, w)
        self._apply_tree_filter()
        self._syncing = False

    def _apply_tree_filter(self) -> None:
        text = self.search_edit.text().strip().lower()
        visible = self._visible_types()
        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            shown = 0
            for j in range(top.childCount()):
                it = top.child(j)
                dev = self.topology.devices.get(it.data(0, ROLE_ID))
                ok = dev is not None and dev.device_type in visible and \
                    (not text or text in _search_text(dev))
                it.setHidden(not ok)
                shown += ok
            top.setHidden(shown == 0)

    def _tree_selection_changed(self) -> None:
        if self._syncing or not self._scene:
            return
        ids = [it.data(0, ROLE_ID) for it in self.tree.selectedItems()
               if it.data(0, ROLE_ID)]
        self._syncing = True
        self._scene.clearSelection()
        for nid in ids:
            item = self._scene.nodes.get(nid)
            if item:
                item.setSelected(True)
        if ids and ids[-1] in self._scene.nodes:
            self.view.centerOn(self._scene.nodes[ids[-1]])
        self._syncing = False
        self._update_props()

    def _tree_double_clicked(self, item: QTreeWidgetItem, _col: int) -> None:
        nid = item.data(0, ROLE_ID)
        if nid:
            self._edit_device(nid)

    def _scene_selection_changed(self) -> None:
        if self._syncing or not self._scene:
            return
        ids = {n.device.node_id for n in self._scene.selectedItems()
               if isinstance(n, NodeItem)}
        self._syncing = True
        self.tree.clearSelection()
        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            for j in range(top.childCount()):
                it = top.child(j)
                if it.data(0, ROLE_ID) in ids:
                    it.setSelected(True)
                    self.tree.scrollToItem(it)
        self._syncing = False
        self._update_props()

    def _selected_device(self) -> Optional[Device]:
        if not self._scene:
            return None
        nodes = [n for n in self._scene.selectedItems()
                 if isinstance(n, NodeItem)]
        return nodes[-1].device if len(nodes) >= 1 else None

    def _update_props(self) -> None:
        dev = self._selected_device()
        self.edit_btn.setEnabled(dev is not None)
        if dev is None:
            self.props.setHtml(
                "<p style='color:#7f8c8d'>Выберите устройство на схеме или в "
                "списке.</p>" + self._summary_html())
            return
        self.props.setHtml(_device_html(dev, self.topology))

    def _summary_html(self) -> str:
        counts: dict[str, int] = {}
        for d in self.topology.devices.values():
            if not d.is_virtual:
                counts[d.device_type] = counts.get(d.device_type, 0) + 1
        if not counts:
            return ("<p>Схема пуста. Укажите подсети на панели "
                    "«Сканирование» или откройте сохранённый проект.</p>")
        rows = "".join(
            f"<tr><td>{html.escape(DEVICE_TYPE_LABELS.get(t, t))}</td>"
            f"<td align='right'><b>{n}</b></td></tr>"
            for t, n in sorted(counts.items(), key=lambda kv: -kv[1]))
        return f"<h3>Сводка</h3><table width='100%'>{rows}</table>"

    def _edit_selected(self) -> None:
        dev = self._selected_device()
        if dev:
            self._edit_device(dev.node_id)

    def _edit_device(self, node_id: str) -> None:
        dev = self.topology.devices.get(node_id)
        if not dev:
            return
        old_subnet, old_ip = dev.subnet, dev.ip
        if DeviceEditDialog(dev, self.topology, self).exec_() == QDialog.Accepted:
            self._modified = True
            if dev.subnet != old_subnet or dev.ip != old_ip:
                self._refresh_scene()
            else:
                item = self._scene.nodes.get(node_id)
                if item:
                    item.refresh()
                self._scene.apply_filter(self._visible_types())
                self._populate_tree()
                self._update_props()
                self._update_status()
            self._select_node(node_id)

    def _select_node(self, node_id: str, center: bool = False) -> None:
        item = self._scene.nodes.get(node_id) if self._scene else None
        if not item:
            return
        self._scene.clearSelection()
        item.setSelected(True)
        if center:
            self.view.centerOn(item)

    # ── Поиск и фильтр ───────────────────────────────────────────────────────

    def _focus_search(self) -> None:
        self.search_edit.setFocus()
        self.search_edit.selectAll()

    def _on_search(self, text: str) -> None:
        t = text.strip().lower()
        if not self._scene:
            return
        if not t:
            self._search_hits = []
            self._scene.set_highlight(None)
        else:
            hits = [nid for nid, d in self.topology.devices.items()
                    if t in _search_text(d)
                    and d.device_type in self._visible_types()]
            hits.sort(key=lambda n: ip_sort_key(self.topology.devices[n].ip))
            self._search_hits = hits
            self._scene.set_highlight(set(hits))
            self.statusBar().showMessage(
                f"Найдено: {len(hits)}" + ("  ·  Enter — следующее"
                                           if hits else ""), 4000)
        self._search_pos = -1
        self._apply_tree_filter()

    def _search_next(self) -> None:
        if not self._search_hits:
            return
        self._search_pos = (self._search_pos + 1) % len(self._search_hits)
        self._select_node(self._search_hits[self._search_pos], center=True)

    def _set_all_types(self, checked: bool) -> None:
        for a in self.type_actions.values():
            a.blockSignals(True)
            a.setChecked(checked)
            a.blockSignals(False)
        self._on_filter_changed()

    def _on_filter_changed(self, *_args) -> None:
        if self._scene:
            self._scene.apply_filter(self._visible_types())
        self._apply_tree_filter()
        hidden = len(set(DEVICE_TYPES) - self._visible_types())
        self.filter_btn.setText("Типы" + (f" (скрыто {hidden})" if hidden else ""))
        self._update_status()

    # ── Раскладка ────────────────────────────────────────────────────────────

    def _layout_mode(self) -> str:
        return self.layout_combo.currentData() or "tree"

    def _select_layout_ui(self, mode: str) -> None:
        idx = self.layout_combo.findData(mode)
        self.layout_combo.setCurrentIndex(max(idx, 0))
        if mode in self.layout_actions:
            self.layout_actions[mode].setChecked(True)

    def _set_layout(self, mode: str) -> None:
        self._select_layout_ui(mode)
        self._relayout()

    def _relayout(self) -> None:
        mode = self._layout_mode()
        self._select_layout_ui(mode)
        if not self.topology.devices:
            self.topology.layout_mode = mode
            return
        self._scene.relayout(mode)
        self._refresh_scene(fit=True)
        self._modified = True
        self._update_title()

    # ── Сканирование ─────────────────────────────────────────────────────────

    def _fill_local_subnet(self) -> None:
        subnet = guess_local_subnet()
        if subnet:
            self.subnets_edit.setText(subnet)
        else:
            QMessageBox.information(self, "Подсеть",
                                    "Не удалось определить подсеть компьютера.")

    def _on_scan(self) -> None:
        import ipaddress
        raw = self.subnets_edit.text().strip()
        subnets = [p.strip() for p in raw.replace(",", " ").split() if p.strip()]
        if not subnets:
            QMessageBox.warning(self, "Сканирование",
                                "Укажите хотя бы одну подсеть, например "
                                "192.168.1.0/24")
            self.subnets_edit.setFocus()
            return
        bad = []
        for s in subnets:
            try:
                ipaddress.ip_network(s, strict=False)
            except ValueError:
                bad.append(s)
        if bad:
            QMessageBox.warning(self, "Сканирование",
                                "Некорректные подсети: " + ", ".join(bad))
            return
        if self._modified and self.topology.devices:
            r = QMessageBox.question(
                self, "Сканирование",
                "Текущая схема будет заменена результатами сканирования. "
                "Продолжить?", QMessageBox.Yes | QMessageBox.No)
            if r != QMessageBox.Yes:
                return
        self._save_settings()
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress.setRange(0, 0)
        self.progress_label.setText("Запуск…")
        self.dock_log.show()
        self._worker = ScanWorker(
            subnets=subnets,
            community=self.community_edit.text().strip() or "public",
            parallel=self.parallel_cb.isChecked(),
            timeout=self.timeout_spin.value(),
            max_hosts=self.max_hosts_spin.value(),
            layout_mode=self._layout_mode())
        self._worker.progress.connect(self._on_scan_progress)
        self._worker.finished_ok.connect(self._on_scan_done)
        self._worker.failed.connect(self._on_scan_error)
        self._worker.start()

    def _on_stop(self) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.requestInterruption()
            self.stop_btn.setEnabled(False)
            self.progress_label.setText("Остановка после текущей подсети…")

    def _on_scan_progress(self, done: int, total: int, msg: str) -> None:
        if total and done:
            self.progress.setRange(0, total)
            self.progress.setValue(done)
            self.progress.setFormat(f"{done} / {total}")
        self.progress_label.setText(msg)
        self.statusBar().showMessage(msg)

    def _scan_finished_ui(self) -> None:
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress.setRange(0, 1)
        self.progress.setValue(1)

    def _on_scan_done(self, topology: NetworkTopology) -> None:
        self._scan_finished_ui()
        self.topology = topology
        self._current_file = None
        self._modified = bool(topology.devices)
        self._refresh_scene(fit=True)
        n = sum(1 for d in topology.devices.values() if not d.is_virtual)
        msg = f"Готово: найдено устройств — {n}"
        self.progress_label.setText(msg)
        self.statusBar().showMessage(msg, 8000)
        if n:
            self.dock_devices.raise_()
        else:
            QMessageBox.information(
                self, "Сканирование",
                "Устройства не найдены. Проверьте подсеть, права "
                "администратора и наличие nmap / Npcap (см. журнал).")

    def _on_scan_error(self, msg: str) -> None:
        self._scan_finished_ui()
        self.progress_label.setText("Ошибка сканирования")
        QMessageBox.critical(self, "Ошибка сканирования", msg)

    def _append_log(self, line: str) -> None:
        self.log_view.appendPlainText(line)

    # ── Правка ───────────────────────────────────────────────────────────────

    def _add_device_dialog(self) -> None:
        dev = Device(ip="0.0.0.0")
        if DeviceEditDialog(dev, self.topology, self).exec_() == QDialog.Accepted:
            center = self.view.mapToScene(self.view.viewport().rect().center())
            dev.position = (center.x(), center.y())
            self._scene.add_device(dev)
            self._select_node(dev.node_id)

    def _delete_selected(self) -> None:
        if not self._scene:
            return
        sel = self._scene.selectedItems()
        nodes = [i for i in sel if isinstance(i, NodeItem)]
        if nodes and QMessageBox.question(
                self, "Удалить?", f"Удалить выбранные устройства: {len(nodes)}?",
                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        self._scene.delete_selected()

    def _auto_merge(self) -> None:
        n = self.topology.merge_by_mac()
        if n:
            self.topology.apply_layout(self._layout_mode())
            self._modified = True
        self._refresh_scene(fit=bool(n))
        QMessageBox.information(self, "Объединение по MAC",
                                f"Объединено групп: {n}")

    def _update_oui_db(self) -> None:
        class OUIWorker(QThread):
            done = pyqtSignal(bool, str)

            def run(self) -> None:
                try:
                    from oui_db import OUIDatabase
                    db = OUIDatabase.get()
                    ok = db.update_database()
                    self.done.emit(ok, db.stats())
                except Exception as e:  # noqa: BLE001
                    self.done.emit(False, str(e))

        self._oui_worker = OUIWorker()

        def on_done(ok: bool, msg: str) -> None:
            if ok:
                QMessageBox.information(self, "OUI-база обновлена", msg)
            else:
                QMessageBox.warning(self, "Ошибка OUI",
                                    msg or "Нет доступа к сети")
        self._oui_worker.done.connect(on_done)
        self.statusBar().showMessage("Обновление OUI-базы…")
        self._oui_worker.start()

    def _toggle_link_mode(self, checked: bool) -> None:
        if not self._scene:
            return
        if checked:
            sel = self._selected_device()
            self._scene.start_link_mode(sel.node_id if sel else None)
            self.statusBar().showMessage(
                "Режим связи: кликните " + ("второй узел" if sel else
                                            "первый, затем второй узел")
                + "  ·  клик по пустому месту — отмена")
        else:
            self._scene.stop_link_mode()
            self.statusBar().clearMessage()

    # ── Файлы ────────────────────────────────────────────────────────────────

    def _confirm_discard(self) -> bool:
        if not self._modified or not self.topology.devices:
            return True
        r = QMessageBox.question(
            self, "Несохранённые изменения", "Сохранить изменения?",
            QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel)
        if r == QMessageBox.Save:
            return self._save_file()
        return r == QMessageBox.Discard

    def _open_file(self) -> None:
        if not self._confirm_discard():
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Открыть проект", self._last_dir(),
            "Проект Net Topology (*.json);;Все файлы (*)")
        if path:
            self.load_file(path)

    def load_file(self, path: str) -> bool:
        topo = NetworkTopology()
        try:
            topo.load_json(path)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Ошибка открытия",
                                 f"Не удалось открыть {path}:\n{exc}")
            return False
        self.topology = topo
        self._current_file = path
        self._modified = False
        self._remember_dir(path)
        self._select_layout_ui(topo.layout_mode)
        self._refresh_scene(fit=True)
        self.statusBar().showMessage(f"Открыто: {path}", 5000)
        return True

    def _save_file(self) -> bool:
        if not self._current_file:
            return self._save_as()
        try:
            self.topology.save_json(self._current_file)
        except OSError as exc:
            QMessageBox.critical(self, "Ошибка сохранения", str(exc))
            return False
        self._modified = False
        self._update_title()
        self.statusBar().showMessage(f"Сохранено: {self._current_file}", 5000)
        return True

    def _save_as(self) -> bool:
        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить проект",
            os.path.join(self._last_dir(), "topology.json"),
            "Проект Net Topology (*.json)")
        if not path:
            return False
        if not path.lower().endswith(".json"):
            path += ".json"
        self._current_file = path
        self._remember_dir(path)
        return self._save_file()

    def _export(self, ext: str) -> None:
        if not self.topology.devices:
            QMessageBox.information(self, "Экспорт", "Схема пуста.")
            return
        title = {**EXPORT_FORMATS, **QT_EXPORTS}[ext]
        base = os.path.splitext(os.path.basename(self._current_file or
                                                 "topology"))[0]
        path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт", os.path.join(self._last_dir(), base + ext), title)
        if not path:
            return
        if not path.lower().endswith(ext):
            path += ext
        try:
            if ext == ".png":
                self.export_png(path)
            elif ext == ".pdf":
                self.export_pdf(path)
            else:
                export_topology(self.topology, path)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Ошибка экспорта")
            QMessageBox.critical(self, "Ошибка экспорта", str(exc))
            return
        self._remember_dir(path)
        self.statusBar().showMessage(f"Экспортировано: {path}", 8000)

    def _export_rect(self) -> QRectF:
        return self._scene.itemsBoundingRect().adjusted(-30, -30, 30, 30)

    def _render_clean(self, painter: QPainter, target: QRectF) -> None:
        """Рисует сцену без выделения и подсветки поиска."""
        selected = self._scene.selectedItems()
        self._scene.clearSelection()
        self._scene.set_highlight(None)
        # Кэшированные элементы рисуются растром — для вектора (PDF) и
        # чёткого PNG отключаем кэш на время экспорта
        nodes = list(self._scene.nodes.values())
        for n in nodes:
            n.setCacheMode(QGraphicsItem.NoCache)
        try:
            self._scene.render(painter, target, self._export_rect())
        finally:
            for n in nodes:
                n.setCacheMode(QGraphicsItem.DeviceCoordinateCache)
            for it in selected:
                it.setSelected(True)
            if self.search_edit.text().strip():
                self._on_search(self.search_edit.text())

    def export_png(self, path: str, scale: float = 2.0) -> None:
        rect = self._export_rect()
        max_side = 16000
        scale = min(scale, max_side / max(rect.width(), rect.height(), 1))
        img = QImage(int(rect.width() * scale), int(rect.height() * scale),
                     QImage.Format_ARGB32)
        img.fill(QColor("#ffffff"))
        p = QPainter(img)
        p.setRenderHints(QPainter.Antialiasing | QPainter.TextAntialiasing
                         | QPainter.SmoothPixmapTransform)
        self._render_clean(p, QRectF(0, 0, img.width(), img.height()))
        p.end()
        if not img.save(path, "PNG"):
            raise OSError(f"Не удалось записать {path}")

    def export_pdf(self, path: str) -> None:
        from PyQt5.QtCore import QMarginsF, QSizeF
        from PyQt5.QtGui import QPageLayout, QPageSize
        from PyQt5.QtPrintSupport import QPrinter
        rect = self._export_rect()
        printer = QPrinter(QPrinter.HighResolution)
        printer.setOutputFormat(QPrinter.PdfFormat)
        printer.setOutputFileName(path)
        printer.setCreator(f"{APP_NAME} {APP_VERSION}")
        printer.setDocName("Топология сети")
        # Страница под размер схемы: 1 px сцены = 0,75 pt (96 dpi).
        # Формат PDF ограничивает сторону страницы ~14 400 pt — большие
        # схемы уменьшаем (вектор, качество не теряется).
        pts = .75 * min(1.0, 14000 / (max(rect.width(), rect.height()) * .75))
        size = QPageSize(QSizeF(rect.width() * pts, rect.height() * pts),
                         QPageSize.Point, "Topology")
        printer.setPageLayout(QPageLayout(size, QPageLayout.Portrait,
                                          QMarginsF(0, 0, 0, 0)))
        p = QPainter()
        if not p.begin(printer):
            raise OSError(f"Не удалось создать PDF {path}")
        p.setRenderHints(QPainter.Antialiasing | QPainter.TextAntialiasing)
        self._render_clean(p, QRectF(p.viewport()))
        p.end()

    # ── Справка ──────────────────────────────────────────────────────────────

    def _show_legend(self) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle("Обозначения")
        v = QVBoxLayout(dlg)
        lw = QListWidget()
        lw.setIconSize(QSize(28, 28))
        for t in DEVICE_TYPES:
            lw.addItem(QListWidgetItem(type_icon(t, 28), DEVICE_TYPE_LABELS[t]))
        v.addWidget(QLabel("<b>Типы устройств</b>"))
        v.addWidget(lw)
        from visual import LINK_STYLES
        rows = "".join(
            f"<tr><td><span style='color:{st.color};font-size:16px'>"
            f"{'┅┅┅' if st.dash else '━━━'}</span></td>"
            f"<td>{html.escape(link_label(k))}</td></tr>"
            for k, st in LINK_STYLES.items() if k)
        lbl = QLabel("<b>Связи</b><table>" + rows + "</table>"
                     "<p><b>Бейджи:</b> GW — шлюз подсети, ★ — несколько "
                     "интерфейсов, RDP/SSH/TEL/VNC/WRM/SNMP — открытые службы.</p>")
        lbl.setWordWrap(True)
        v.addWidget(lbl)
        bb = QDialogButtonBox(QDialogButtonBox.Close)
        bb.rejected.connect(dlg.reject)
        v.addWidget(bb)
        dlg.resize(420, 640)
        dlg.exec_()

    def _show_help(self) -> None:
        QMessageBox.information(self, "Управление", (
            "<table cellpadding=3>"
            "<tr><td><b>Колесо</b></td><td>масштаб под курсором</td></tr>"
            "<tr><td><b>Средняя кнопка / Пробел</b></td><td>панорама</td></tr>"
            "<tr><td><b>ЛКМ</b></td><td>выбор и перемещение узла</td></tr>"
            "<tr><td><b>Shift + ЛКМ</b></td><td>перемещение всей подсети</td></tr>"
            "<tr><td><b>Двойной клик</b></td><td>свойства устройства</td></tr>"
            "<tr><td><b>Ctrl + клик по связи</b></td><td>удалить связь</td></tr>"
            "<tr><td><b>Delete</b></td><td>удалить выбранное</td></tr>"
            "<tr><td><b>Ctrl+K</b></td><td>режим добавления связи</td></tr>"
            "<tr><td><b>Ctrl+F, Enter</b></td><td>поиск, следующее совпадение</td></tr>"
            "<tr><td><b>F / Ctrl+0</b></td><td>вписать / масштаб 100%</td></tr>"
            "<tr><td><b>Ctrl+L</b></td><td>перестроить раскладку</td></tr>"
            "</table>"))

    def _show_about(self) -> None:
        QMessageBox.about(self, "О программе", (
            f"<h3>{APP_NAME} {APP_VERSION}</h3>"
            "<p>Сканер и редактор топологии сети.</p>"
            "<p>Экспорт: HTML, SVG, PDF, PNG, draw.io, GraphML, CSV.</p>"))

    # ── Drag & drop / закрытие ───────────────────────────────────────────────

    def dragEnterEvent(self, event) -> None:
        urls = event.mimeData().urls() if event.mimeData().hasUrls() else []
        if urls and urls[0].toLocalFile().lower().endswith(".json"):
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        path = event.mimeData().urls()[0].toLocalFile()
        if self._confirm_discard():
            self.load_file(path)

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key_Escape:
            if self.a_link.isChecked():
                self.a_link.setChecked(False)
                self._toggle_link_mode(False)
            elif self.search_edit.text():
                self.search_edit.clear()
            elif self._scene:
                self._scene.clearSelection()
            return
        super().keyPressEvent(event)

    def closeEvent(self, event) -> None:
        if not self._confirm_discard():
            event.ignore()
            return
        if self._worker and self._worker.isRunning():
            self._worker.requestInterruption()
            self._worker.wait(3000)
        self._save_settings()
        logging.getLogger().removeHandler(self._log_handler)
        event.accept()


# ═══════════════════════════════════════════════════════════════════════════
# Вспомогательные
# ═══════════════════════════════════════════════════════════════════════════

def _search_text(dev: Device) -> str:
    return " ".join(filter(None, [
        dev.display_name(), dev.hostname or "", dev.netbios_name,
        " ".join(dev.all_ips()), dev.mac or "", dev.vendor or "",
        dev.os_name, dev.model, dev.subnet, dev.type_label, dev.notes,
        dev.location])).lower()


def _device_html(dev: Device, topology: NetworkTopology) -> str:
    def row(k: str, v) -> str:
        if v in (None, "", [], {}):
            return ""
        return (f"<tr><td style='color:#5d6d7e;padding-right:8px' "
                f"valign='top'>{html.escape(k)}</td>"
                f"<td>{html.escape(str(v))}</td></tr>")

    nbrs = sorted(topology.devices[n].display_name()
                  for n in topology.graph.neighbors(dev.node_id)
                  if n in topology.devices)
    ports = ", ".join(str(p) for p in dev.open_ports)
    conf = f" · уверенность {dev.confidence}%" if dev.confidence else ""
    parts = [
        f"<h3 style='margin-bottom:2px'>{html.escape(dev.display_name())}</h3>",
        f"<div style='color:#5d6d7e'>{html.escape(dev.type_label)}{conf}</div>",
        "<table style='margin-top:8px'>",
        row("IP", ", ".join(dev.all_ips()) if not dev.is_virtual else ""),
        row("Имя хоста", dev.hostname), row("NetBIOS", dev.netbios_name),
        row("MAC", dev.mac), row("Производитель", dev.vendor),
        row("ОС", dev.os_name), row("Модель", dev.model),
        row("Подсеть", dev.subnet),
        row("Шлюз", "да" if dev.is_gateway else ""),
        row("Хопов", dev.hops), row("TTL", dev.ttl), row("Порты", ports),
        row("Расположение", dev.location), row("Соседи", ", ".join(nbrs)),
        row("Заметки", dev.notes), "</table>",
    ]
    if dev.evidence:
        parts.append("<p style='margin-top:10px'><b>Почему такой тип</b></p>"
                     "<ul style='margin-left:-20px;color:#5d6d7e'>")
        parts += [f"<li>{html.escape(e)}</li>" for e in dev.evidence[:20]]
        parts.append("</ul>")
    return "".join(parts)


def run_gui(topology: NetworkTopology, path: Optional[str] = None) -> None:
    if hasattr(Qt, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, "AA_UseHighDpiPixmaps"):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(ORG_NAME)
    app.setStyle("Fusion")
    w = MainWindow(topology)
    if path:
        w._current_file = path
        w._update_title()
    w.show()
    sys.exit(app.exec_())
