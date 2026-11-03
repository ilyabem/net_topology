"""
layout.py — раскладка топологии без наложений (чистый Python, без Qt/numpy).

Режимы:
  tree     — иерархическое дерево сверху вниз (по умолчанию)
  tree-lr  — то же дерево слева направо
  organic  — силовая раскладка, привязанная к сетке

Дерево:
  * Остовное дерево строится по «весу» связей (LLDP/FDB важнее
    предполагаемых), корень — ближайший к сканеру шлюз.
  * Каждое поддерево занимает собственную полосу, поэтому поддеревья
    не пересекаются по построению.
  * Если у узла много «листьев», они укладываются сеткой, а связи к ним
    идут «гребёнкой» по зазорам между карточками — линии не проходят
    через чужие узлы.

Все координаты — центры карточек узлов размером NODE_W × NODE_H.
"""

from __future__ import annotations

import math
import random
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING

import networkx as nx

from model import (DEVICE_TYPES, LINK_PRIORITY, ROUTING_TYPES, TYPE_RANK,
                   ip_sort_key)

if TYPE_CHECKING:
    from model import NetworkTopology

# ─── Геометрия карточки узла (общая для GUI и экспорта) ──────────────────────
NODE_W = 156.0
NODE_H = 104.0
MARGIN = 60.0

ROW_MAX = 6          # больше листьев у одного родителя → сетка
ASPECT = 1.6         # желаемое соотношение сторон блока листьев

LAYOUT_MODES: dict[str, str] = {
    "tree":    "Дерево ↓",
    "tree-lr": "Дерево →",
    "organic": "Органическая",
}

Point = tuple[float, float]


@dataclass(frozen=True)
class _Geom:
    sb: float   # размер узла вдоль «ширины» дерева
    sd: float   # размер узла вдоль «глубины» дерева
    gb: float   # зазор между соседями
    gd: float   # зазор между уровнями
    gr: float   # зазор между рядами блока листьев


# Зазор между соседями 64 px: «гребёнка» связей идёт посередине (32 px),
# а зоны подсетей соседних веток не касаются (отступы зон 38 + 16 px).
_TB = _Geom(sb=NODE_W, sd=NODE_H, gb=64.0, gd=100.0, gr=30.0)
# В режиме «слева направо» соседние полосы разделены по вертикали; зазор
# должен вмещать заголовок зоны подсети (visual.ZONE_LABEL_H + ZONE_PAD).
_LR = _Geom(sb=NODE_H, sd=NODE_W, gb=60.0, gd=120.0, gr=44.0)

# Расстояние от края карточки до «гребёнки» связей (середина зазора)
LANE_GAP_TB = _TB.gb / 2
LANE_GAP_LR = _LR.gb / 2


# ═══════════════════════════════════════════════════════════════════════════
# Публичный API
# ═══════════════════════════════════════════════════════════════════════════

def compute_layout(topology: "NetworkTopology", mode: str = "tree"
                   ) -> tuple[dict[str, Point], dict[tuple[str, str], list[Point]]]:
    """Возвращает (позиции центров узлов, маршруты связей parent→child)."""
    if not topology.devices:
        return {}, {}
    if mode == "organic":
        positions = _organic(topology)
        routes: dict[tuple[str, str], list[Point]] = {}
    else:
        lr = mode == "tree-lr"
        positions, routes = _tree(topology, _LR if lr else _TB, lr)
    return _normalize(positions, routes)


def route_is_valid(points: list, src_pos: Point, dst_pos: Point) -> bool:
    """Маршрут действителен, если его концы лежат на карточках узлов."""
    if not points or len(points) < 2:
        return False
    return (_on_card(points[0], src_pos) and _on_card(points[-1], dst_pos))


def reanchor_route(points: list, start: Point | None, end: Point | None
                   ) -> list[Point] | None:
    """
    Перестраивает ортогональный маршрут дерева, когда пользователь сдвинул
    один или оба конца: узел заново подключается к «шине» своего уровня,
    остальная часть маршрута (гребёнка по зазорам) сохраняется.

    start / end — новые центры сдвинутых узлов (None — узел на месте).
    Возвращает None, если маршрут не древесный (тогда рисуется прямая).
    """
    pts = [(float(p[0]), float(p[1])) for p in points]
    if len(pts) == 2:
        # Прямой отрезок родитель → ребёнок (ребёнок ровно под родителем):
        # восстанавливаем шину посередине
        (x0, y0), (x1, y1) = pts
        if abs(x0 - x1) < 1e-6:
            mid = (y0 + y1) / 2
            pts = [(x0, y0), (x0, mid), (x1, mid), (x1, y1)]
        elif abs(y0 - y1) < 1e-6:
            mid = (x0 + x1) / 2
            pts = [(x0, y0), (mid, y0), (mid, y1), (x1, y1)]
        else:
            return None
    if len(pts) < 3:
        return None
    if abs(pts[0][0] - pts[1][0]) < 1e-6:          # дерево сверху вниз
        swap, half = False, NODE_H / 2
    elif abs(pts[0][1] - pts[1][1]) < 1e-6:        # дерево слева направо
        swap, half = True, NODE_W / 2
        pts = [(y, x) for x, y in pts]
        start = (start[1], start[0]) if start else None
        end = (end[1], end[0]) if end else None
    else:
        return None
    bus = pts[1][1]
    if start is not None:
        sx, sy = start
        anchor = (sx, sy + half) if sy + half <= bus else (sx, sy - half)
        pts = [anchor, (sx, bus)] + pts[1:]
    if end is not None:
        ex, ey = end
        k = max(i for i, p in enumerate(pts) if abs(p[1] - bus) < 1e-6)
        anchor = (ex, ey - half) if ey - half >= bus else (ex, ey + half)
        pts = pts[:k + 1] + [(ex, bus), anchor]
    pts = _simplify(pts)
    if swap:
        pts = [(y, x) for x, y in pts]
    return pts


def find_overlaps(positions: dict[str, Point], w: float = NODE_W,
                  h: float = NODE_H) -> list[tuple[str, str]]:
    """Пары узлов, чьи карточки пересекаются (sweep по X)."""
    items = sorted(positions.items(), key=lambda kv: kv[1][0])
    result = []
    active: list[tuple[str, Point]] = []
    for nid, (x, y) in items:
        active = [(a, p) for a, p in active if x - p[0] < w]
        for a, (ax, ay) in active:
            if abs(x - ax) < w - 1e-6 and abs(y - ay) < h - 1e-6:
                result.append((a, nid))
        active.append((nid, (x, y)))
    return result


def layout_bounds(positions: dict[str, Point]) -> tuple[float, float, float, float]:
    """(min_x, min_y, max_x, max_y) по краям карточек."""
    if not positions:
        return (0.0, 0.0, 0.0, 0.0)
    xs = [p[0] for p in positions.values()]
    ys = [p[1] for p in positions.values()]
    return (min(xs) - NODE_W / 2, min(ys) - NODE_H / 2,
            max(xs) + NODE_W / 2, max(ys) + NODE_H / 2)


# ═══════════════════════════════════════════════════════════════════════════
# Дерево
# ═══════════════════════════════════════════════════════════════════════════

def _type_index(t: str) -> int:
    try:
        return DEVICE_TYPES.index(t)
    except ValueError:
        return len(DEVICE_TYPES)


def _spanning_forest(topology: "NetworkTopology"
                     ) -> tuple[list[str], dict[str, list[str]]]:
    g = topology.graph
    devs = topology.devices

    def root_key(n: str) -> tuple:
        d = devs[n]
        upstream = (d.hops if d.device_type in ROUTING_TYPES
                    and d.hops is not None else 1000)
        return (upstream, not d.is_gateway, -TYPE_RANK.get(d.device_type, 0),
                -g.degree(n), ip_sort_key(d.ip), n)

    # Максимальное остовное дерево: достоверные связи важнее предполагаемых
    weighted = nx.Graph()
    weighted.add_nodes_from(g.nodes)
    for u, v, data in g.edges(data=True):
        rank = min(TYPE_RANK.get(devs[u].device_type, 0),
                   TYPE_RANK.get(devs[v].device_type, 0))
        weighted.add_edge(u, v, weight=LINK_PRIORITY.get(
            data.get("label", ""), 0) * 10 + rank)
    tree = nx.maximum_spanning_tree(weighted, weight="weight")

    children: dict[str, list[str]] = {n: [] for n in g.nodes}
    roots: list[str] = []
    components = [sorted(c) for c in nx.connected_components(tree)]
    components.sort(key=lambda c: min(root_key(n) for n in c))
    for comp in components:
        root = min(comp, key=root_key)
        roots.append(root)
        seen = {root}
        queue = deque([root])
        while queue:
            u = queue.popleft()
            for v in sorted(tree.neighbors(u)):
                if v not in seen:
                    seen.add(v)
                    children[u].append(v)
                    queue.append(v)

    # Порядок детей: ветки в другие подсети → ветки своей подсети → листья
    for p, kids in children.items():
        parent = devs[p]

        def order(c: str, parent=parent) -> tuple:
            d = devs[c]
            has_kids = bool(children[c])
            other_net = has_kids and (d.is_multihomed or d.device_type in
                                      ROUTING_TYPES or d.subnet != parent.subnet)
            group = 0 if other_net else (1 if has_kids else 2)
            return (group, d.subnet if group == 0 else "",
                    _type_index(d.device_type), ip_sort_key(d.ip), c)
        kids.sort(key=order)
    return roots, children


def _block_cols(n: int, geo: _Geom) -> int:
    ideal = math.ceil(math.sqrt(n * (geo.sd + geo.gr) / (geo.sb + geo.gb)
                                * ASPECT))
    return max(1, min(n, max(ROW_MAX, ideal)))


def _tree(topology: "NetworkTopology", geo: _Geom, transpose: bool
          ) -> tuple[dict[str, Point], dict[tuple[str, str], list[Point]]]:
    roots, children = _spanning_forest(topology)

    # Одиночные узлы без связей собираем в общий блок в конце
    isolated = [r for r in roots if not children[r]]
    trees = [r for r in roots if children[r]]

    units: dict[str, list[tuple[str, object]]] = {}
    width: dict[str, float] = {}
    depth: dict[str, float] = {}

    def unit_size(kind: str, payload) -> tuple[float, float]:
        if kind == "node":
            return width[payload], depth[payload]
        cols = _block_cols(len(payload), geo)
        rows = math.ceil(len(payload) / cols)
        return (cols * geo.sb + (cols - 1) * geo.gb,
                rows * geo.sd + (rows - 1) * geo.gr)

    # Пост-порядок без рекурсии
    order: list[str] = []
    stack = list(trees)
    while stack:
        n = stack.pop()
        order.append(n)
        stack.extend(children[n])
    for n in reversed(order):
        kids = children[n]
        if not kids:
            width[n], depth[n] = geo.sb, geo.sd
            continue
        leaves = [c for c in kids if not children[c]]
        subs = [c for c in kids if children[c]]
        u: list[tuple[str, object]] = [("node", c) for c in subs]
        if len(leaves) > ROW_MAX:
            u.append(("block", leaves))
        else:
            u.extend(("node", c) for c in leaves)
        units[n] = u
        sizes = [unit_size(k, p) for k, p in u]
        total = sum(s[0] for s in sizes) + geo.gb * (len(sizes) - 1)
        width[n] = max(geo.sb, total)
        depth[n] = geo.sd + geo.gd + max(s[1] for s in sizes)

    pos: dict[str, Point] = {}          # (b, d) — центр
    routes: dict[tuple[str, str], list[Point]] = {}

    def place(root: str, b0: float, d0: float) -> None:
        work = [(root, b0, d0)]
        while work:
            n, nb0, nd0 = work.pop()
            cb = nb0 + width[n] / 2
            pos[n] = (cb, nd0 + geo.sd / 2)
            if n not in units:
                continue
            sizes = [unit_size(k, p) for k, p in units[n]]
            total = sum(s[0] for s in sizes) + geo.gb * (len(sizes) - 1)
            start = nb0 + (width[n] - total) / 2
            child_d = nd0 + geo.sd + geo.gd
            bus = nd0 + geo.sd + geo.gd / 2
            top = (cb, nd0 + geo.sd)
            for (kind, payload), (uw, _ud) in zip(units[n], sizes):
                if kind == "node":
                    c = payload
                    ccb = start + uw / 2
                    routes[(n, c)] = _simplify(
                        [top, (cb, bus), (ccb, bus), (ccb, child_d)])
                    work.append((c, start, child_d))
                else:
                    leaves = payload
                    cols = _block_cols(len(leaves), geo)
                    for i, c in enumerate(leaves):
                        col, row = i % cols, i // cols
                        left = start + col * (geo.sb + geo.gb)
                        ctop = child_d + row * (geo.sd + geo.gr)
                        mid = ctop + geo.sd / 2
                        pos[c] = (left + geo.sb / 2, mid)
                        lane = left - geo.gb / 2
                        routes[(n, c)] = _simplify(
                            [top, (cb, bus), (lane, bus), (lane, mid),
                             (left, mid)])
                start += uw + geo.gb

    # Раскладываем деревья рядами, чтобы итог был ближе к экрану по пропорциям
    blocks: list[tuple[str, object, float, float]] = []
    for r in trees:
        blocks.append(("tree", r, width[r], depth[r]))
    if isolated:
        def iso_key(n: str) -> tuple:
            d = topology.devices[n]
            return (d.subnet, _type_index(d.device_type), ip_sort_key(d.ip))
        isolated.sort(key=iso_key)
        bw, bd = unit_size("block", isolated)
        blocks.append(("iso", isolated, bw, bd))

    area = sum(b[2] * b[3] for b in blocks)
    target = max(max(b[2] for b in blocks), math.sqrt(area * ASPECT))
    gap_b = geo.gb * 3
    gap_d = geo.gd
    b_cursor = d_cursor = row_depth = 0.0
    for kind, payload, bw, bd in blocks:
        if b_cursor > 0 and b_cursor + bw > target:
            b_cursor = 0.0
            d_cursor += row_depth + gap_d
            row_depth = 0.0
        if kind == "tree":
            place(payload, b_cursor, d_cursor)
        else:
            cols = _block_cols(len(payload), geo)
            for i, c in enumerate(payload):
                col, row = i % cols, i // cols
                pos[c] = (b_cursor + col * (geo.sb + geo.gb) + geo.sb / 2,
                          d_cursor + row * (geo.sd + geo.gr) + geo.sd / 2)
        b_cursor += bw + gap_b
        row_depth = max(row_depth, bd)

    if transpose:
        pos = {n: (d, b) for n, (b, d) in pos.items()}
        routes = {k: [(d, b) for b, d in pts] for k, pts in routes.items()}
    return pos, routes


def _simplify(points: list[Point]) -> list[Point]:
    """Убирает повторы и промежуточные точки на одной прямой."""
    out: list[Point] = []
    for p in points:
        p = (round(p[0], 2), round(p[1], 2))
        if out and abs(out[-1][0] - p[0]) < 1e-6 and abs(out[-1][1] - p[1]) < 1e-6:
            continue
        out.append(p)
    i = 1
    while i < len(out) - 1:
        a, b, c = out[i - 1], out[i], out[i + 1]
        if (abs(a[0] - b[0]) < 1e-6 and abs(b[0] - c[0]) < 1e-6) or \
                (abs(a[1] - b[1]) < 1e-6 and abs(b[1] - c[1]) < 1e-6):
            out.pop(i)
        else:
            i += 1
    return out


# ═══════════════════════════════════════════════════════════════════════════
# Органическая раскладка (Fruchterman–Reingold + привязка к сетке)
# ═══════════════════════════════════════════════════════════════════════════

def _organic(topology: "NetworkTopology") -> dict[str, Point]:
    g = topology.graph
    nodes = sorted(g.nodes, key=lambda n: (topology.devices[n].subnet,
                                           ip_sort_key(topology.devices[n].ip)))
    n = len(nodes)
    cell_w = NODE_W + _TB.gb
    cell_h = NODE_H + _TB.gr
    if n == 1:
        return {nodes[0]: (0.0, 0.0)}

    rng = random.Random(42)
    k = cell_w * 1.3
    side = math.ceil(math.sqrt(n))
    pos = {nd: [(i % side) * k + rng.uniform(-5, 5),
                (i // side) * k + rng.uniform(-5, 5)]
           for i, nd in enumerate(nodes)}
    iterations = max(25, min(150, 30000 // n))
    temp = k * side / 4
    cool = temp / (iterations + 1)
    bucket = k * 2.5

    for _ in range(iterations):
        disp = {nd: [0.0, 0.0] for nd in nodes}
        grid: dict[tuple[int, int], list[str]] = {}
        for nd in nodes:
            key = (int(pos[nd][0] // bucket), int(pos[nd][1] // bucket))
            grid.setdefault(key, []).append(nd)
        for (gx, gy), members in grid.items():
            near = [m for dx in (-1, 0, 1) for dy in (-1, 0, 1)
                    for m in grid.get((gx + dx, gy + dy), [])]
            for a in members:
                ax, ay = pos[a]
                for b in near:
                    if a == b:
                        continue
                    dx, dy = ax - pos[b][0], ay - pos[b][1]
                    dist = math.hypot(dx, dy) or 0.01
                    f = k * k / dist
                    disp[a][0] += dx / dist * f
                    disp[a][1] += dy / dist * f
        for u, v in g.edges:
            dx, dy = pos[u][0] - pos[v][0], pos[u][1] - pos[v][1]
            dist = math.hypot(dx, dy) or 0.01
            f = dist * dist / k
            disp[u][0] -= dx / dist * f
            disp[u][1] -= dy / dist * f
            disp[v][0] += dx / dist * f
            disp[v][1] += dy / dist * f
        for nd in nodes:
            dx, dy = disp[nd]
            length = math.hypot(dx, dy)
            if length > 0:
                step = min(length, temp)
                pos[nd][0] += dx / length * step
                pos[nd][1] += dy / length * step
        temp = max(temp - cool, 1.0)

    # Привязка к сетке: каждая ячейка занята не более чем одним узлом
    order = sorted(nodes, key=lambda nd: -g.degree(nd))
    taken: set[tuple[int, int]] = set()
    result: dict[str, Point] = {}
    for nd in order:
        cx = round(pos[nd][0] / cell_w)
        cy = round(pos[nd][1] / cell_h)
        cell = _nearest_free((cx, cy), taken)
        taken.add(cell)
        result[nd] = (cell[0] * cell_w, cell[1] * cell_h)
    return result


def _nearest_free(cell: tuple[int, int],
                  taken: set[tuple[int, int]]) -> tuple[int, int]:
    if cell not in taken:
        return cell
    cx, cy = cell
    radius = 1
    while True:
        ring = [(cx + dx, cy + dy)
                for dx in range(-radius, radius + 1)
                for dy in range(-radius, radius + 1)
                if max(abs(dx), abs(dy)) == radius]
        ring.sort(key=lambda c: (c[0] - cx) ** 2 + (c[1] - cy) ** 2)
        for c in ring:
            if c not in taken:
                return c
        radius += 1


# ═══════════════════════════════════════════════════════════════════════════
# Общие утилиты
# ═══════════════════════════════════════════════════════════════════════════

def _normalize(pos: dict[str, Point], routes: dict[tuple[str, str], list[Point]]
               ) -> tuple[dict[str, Point], dict[tuple[str, str], list[Point]]]:
    if not pos:
        return pos, routes
    min_x = min(p[0] for p in pos.values()) - NODE_W / 2
    min_y = min(p[1] for p in pos.values()) - NODE_H / 2
    for pts in routes.values():
        for x, y in pts:
            min_x = min(min_x, x)
            min_y = min(min_y, y)
    dx, dy = MARGIN - min_x, MARGIN - min_y
    pos = {n: (round(x + dx, 2), round(y + dy, 2)) for n, (x, y) in pos.items()}
    routes = {k: [(round(x + dx, 2), round(y + dy, 2)) for x, y in pts]
              for k, pts in routes.items()}
    return pos, routes


def _on_card(point, center: Point, tol: float = 0.6) -> bool:
    x, y = float(point[0]), float(point[1])
    return (abs(x - center[0]) <= NODE_W / 2 + tol
            and abs(y - center[1]) <= NODE_H / 2 + tol)
