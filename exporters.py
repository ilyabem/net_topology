"""
exporters.py — выгрузка топологии в переносимые форматы (без Qt).

  .html     интерактивная схема в одном файле: масштаб, поиск, фильтры,
            карточка устройства. Открывается офлайн в любом браузере
            (Windows / macOS / Linux / Android / iOS).
  .svg      векторная схема — масштабируется без потери качества,
            открывается браузером, Inkscape, Illustrator, Visio, LibreOffice.
  .drawio   редактируемая схема diagrams.net / draw.io (веб и десктоп,
            Confluence, VS Code). Из draw.io можно сохранить в .vsdx (Visio).
  .graphml  граф для yEd / Gephi / Cytoscape (с координатами и цветами).
  .csv      инвентаризация устройств для Excel / LibreOffice (разделитель «;»).
  .json     полный формат проекта (открывается обратно в программе).

Использование:
    from exporters import export_topology
    export_topology(topology, "network.html")
"""

from __future__ import annotations

import base64
import csv
import html
import json
import logging
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Callable
from xml.sax.saxutils import escape, quoteattr

from layout import NODE_H, NODE_W
from model import APP_NAME, APP_VERSION, DEVICE_TYPE_LABELS, DEVICE_TYPES
from visual import (BADGE_H, BADGE_W, DETAIL_CHARS, DETAIL_Y, FONT_FAMILY,
                    ICON_SIZE, ICON_TOP, IP_CHARS, IP_Y, TITLE_CHARS, TITLE_Y,
                    ZONE_LABEL_H, card_badges, card_lines, device_tooltip,
                    elide, icon_inner, icon_svg, link_label, link_style,
                    subnet_color, type_color, zone_members, zone_rect)

if TYPE_CHECKING:
    from model import Device, NetworkTopology

logger = logging.getLogger("exporters")

EXPORT_FORMATS: dict[str, str] = {
    ".html":    "Интерактивная схема HTML (*.html)",
    ".svg":     "Векторная схема SVG (*.svg)",
    ".drawio":  "Схема draw.io / diagrams.net (*.drawio)",
    ".graphml": "Граф GraphML для yEd / Gephi (*.graphml)",
    ".csv":     "Инвентаризация CSV (*.csv)",
    ".json":    "Проект Net Topology (*.json)",
}

HEADER_H = 64.0
PAD = 40.0
LEGEND_ROW_H = 26.0
LEGEND_ITEM_W = 200.0


# ═══════════════════════════════════════════════════════════════════════════
# Подготовка геометрии
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class _Zone:
    cidr: str
    x: float
    y: float
    w: float
    h: float
    rgb: tuple[int, int, int]
    count: int


@dataclass
class _Scene:
    nodes: list[tuple[str, float, float]]               # id, cx, cy
    edges: list[tuple[str, str, str, list[tuple[float, float]]]]
    zones: list[_Zone]
    width: float
    height: float
    types: list[str]
    kinds: list[str]


def _prepare(topology: "NetworkTopology") -> _Scene:
    """Позиции → координаты листа (с полями, шапкой и легендой)."""
    topology.place_missing()

    raw_zones = []
    for cidr, nids in zone_members(topology).items():
        pts = [topology.devices[n].position for n in nids]
        raw_zones.append((cidr, zone_rect(pts), len(nids)))

    xs: list[float] = []
    ys: list[float] = []
    for dev in topology.devices.values():
        x, y = dev.position
        xs += [x - NODE_W / 2, x + NODE_W / 2]
        ys += [y - NODE_H / 2, y + NODE_H / 2]
    for _c, (zx, zy, zw, zh), _n in raw_zones:
        xs += [zx, zx + zw]
        ys += [zy, zy + zh]
    edges_raw = []
    for u, v, data in topology.links:
        pts = topology.edge_route(u, v)
        edges_raw.append((u, v, data.get("label", ""), pts))
        for x, y in pts:
            xs.append(x)
            ys.append(y)
    if not xs:
        xs, ys = [0.0, 400.0], [0.0, 200.0]

    dx = PAD - min(xs)
    dy = PAD + HEADER_H - min(ys)
    content_w = max(xs) - min(xs)
    content_h = max(ys) - min(ys)

    types = [t for t in DEVICE_TYPES
             if any(d.device_type == t for d in topology.devices.values())]
    kinds = sorted({k for _u, _v, k, _p in edges_raw})
    width = max(content_w + 2 * PAD, 720.0)
    per_row = max(1, int((width - 2 * PAD) // LEGEND_ITEM_W))
    legend_rows = -(-len(types) // per_row) + -(-len(kinds) // per_row)
    legend_h = (legend_rows * LEGEND_ROW_H + 40) if (types or kinds) else 0
    height = HEADER_H + content_h + 2 * PAD + legend_h

    nodes = [(nid, d.position[0] + dx, d.position[1] + dy)
             for nid, d in topology.devices.items()]
    edges = [(u, v, k, [(x + dx, y + dy) for x, y in pts])
             for u, v, k, pts in edges_raw]
    zones = [_Zone(c, zx + dx, zy + dy, zw, zh, subnet_color(c), n)
             for c, (zx, zy, zw, zh), n in raw_zones]
    return _Scene(nodes, edges, zones, round(width, 1), round(height, 1),
                  types, kinds)


def _title(topology: "NetworkTopology") -> str:
    subnets = topology.meta.get("subnets") or sorted(
        {d.subnet for d in topology.devices.values() if d.subnet})
    if subnets:
        shown = ", ".join(subnets[:4]) + (" …" if len(subnets) > 4 else "")
        return f"Топология сети: {shown}"
    return "Топология сети"


def _subtitle(topology: "NetworkTopology") -> str:
    real = [d for d in topology.devices.values() if not d.is_virtual]
    stamp = datetime.now().strftime("%d.%m.%Y %H:%M")
    return (f"Устройств: {len(real)} · связей: {len(topology.links)} · "
            f"{stamp} · {APP_NAME} {APP_VERSION}")


# ═══════════════════════════════════════════════════════════════════════════
# SVG
# ═══════════════════════════════════════════════════════════════════════════

def _a(value) -> str:
    """Значение XML-атрибута в кавычках."""
    return quoteattr(str(value))


def _f(v: float) -> str:
    return f"{v:.1f}".rstrip("0").rstrip(".")


def _path_d(points: list[tuple[float, float]]) -> str:
    return "M" + " L".join(f"{_f(x)} {_f(y)}" for x, y in points)


def render_svg(topology: "NetworkTopology", interactive: bool = False) -> str:
    """Возвращает SVG-документ схемы. interactive=True — разметка для HTML."""
    sc = _prepare(topology)
    out: list[str] = []
    w, h = sc.width, sc.height
    out.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'xmlns:xlink="http://www.w3.org/1999/xlink" '
        f'width="{_f(w)}" height="{_f(h)}" viewBox="0 0 {_f(w)} {_f(h)}" '
        f'font-family={_a(FONT_FAMILY)} id="topology">')
    out.append(f"<title>{escape(_title(topology))}</title>")
    out.append(f"<desc>{escape(_subtitle(topology))}</desc>")

    out.append("<defs>")
    for t in sc.types:
        out.append(f'<symbol id="ico-{t}" viewBox="0 0 48 48">'
                   f"{icon_inner(t)}</symbol>")
    out.append('<filter id="shadow" x="-10%" y="-10%" width="120%" '
               'height="130%"><feDropShadow dx="0" dy="1.5" stdDeviation="1.6"'
               ' flood-color="#000" flood-opacity="0.18"/></filter>')
    out.append("</defs>")
    out.append("<style>"
               ".t{font-size:11px;font-weight:600;fill:#1c2833}"
               ".ip{font-size:10px;fill:#34495e}"
               ".dt{font-size:9px;fill:#7f8c8d}"
               ".bd{font-size:8px;font-weight:700;fill:#fff}"
               ".zl{font-size:12px;font-weight:700;fill:#2c3e50}"
               ".lg{font-size:11px;fill:#2c3e50}"
               "</style>")
    out.append(f'<rect id="bg" x="0" y="0" width="{_f(w)}" height="{_f(h)}" '
               'fill="#f8f9f9"/>')
    out.append(f'<text x="{_f(PAD)}" y="34" style="font-size:20px;'
               f'font-weight:700;fill:#1b2631">{escape(_title(topology))}</text>')
    out.append(f'<text x="{_f(PAD)}" y="54" style="font-size:12px;'
               f'fill:#5d6d7e">{escape(_subtitle(topology))}</text>')

    # Зоны подсетей
    out.append('<g id="zones">')
    for z in sc.zones:
        r, g, b = z.rgb
        stroke = f"rgb({int(r * .6)},{int(g * .6)},{int(b * .6)})"
        out.append(
            f'<g class="zone" data-subnet={_a(z.cidr)}>'
            f'<rect x="{_f(z.x)}" y="{_f(z.y)}" width="{_f(z.w)}" '
            f'height="{_f(z.h)}" rx="12" fill="rgb({r},{g},{b})" '
            f'fill-opacity="0.28" stroke="{stroke}" stroke-opacity="0.7" '
            f'stroke-width="1.5" stroke-dasharray="6 4"/>'
            f'<text class="zl" x="{_f(z.x + 12)}" '
            f'y="{_f(z.y + ZONE_LABEL_H - 4)}">{escape(z.cidr)} '
            f'<tspan style="font-weight:400;fill:#5d6d7e">· {z.count}</tspan>'
            f'</text></g>')
    out.append("</g>")

    # Связи — под узлами
    out.append('<g id="edges" fill="none" stroke-linejoin="round">')
    for u, v, kind, pts in sc.edges:
        if len(pts) < 2:
            continue
        st = link_style(kind)
        dash = (f' stroke-dasharray="{" ".join(_f(x) for x in st.dash)}"'
                if st.dash else "")
        data = (f' data-src={_a(u)} data-dst={_a(v)}' if interactive else "")
        out.append(f'<path class="edge" d="{_path_d(pts)}" stroke="{st.color}" '
                   f'stroke-width="{_f(st.width)}"{dash}{data}>'
                   f"<title>{escape(link_label(kind))}</title></path>")
    out.append("</g>")

    # Узлы
    out.append('<g id="nodes">')
    for nid, cx, cy in sc.nodes:
        out.append(_svg_node(topology.devices[nid], nid, cx, cy, interactive))
    out.append("</g>")

    out.append(_svg_legend(sc, h))
    out.append("</svg>")
    return "\n".join(out)


def _svg_node(dev: "Device", nid: str, cx: float, cy: float,
              interactive: bool) -> str:
    x0, y0 = cx - NODE_W / 2, cy - NODE_H / 2
    title, ip_line, detail = card_lines(dev)
    border = "#f39c12" if dev.is_multihomed else "#d5d8dc"
    dash = ' stroke-dasharray="5 3"' if dev.is_virtual else ""
    attrs = (f' id={_a("n-" + nid)} data-id={_a(nid)} '
             f'data-type={_a(dev.device_type)}' if interactive else "")
    parts = [f'<g class="node" transform="translate({_f(x0)},{_f(y0)})"{attrs}>',
             f"<title>{escape(device_tooltip(dev))}</title>",
             f'<rect class="card" width="{_f(NODE_W)}" height="{_f(NODE_H)}" '
             f'rx="10" fill="#ffffff" stroke="{border}" '
             f'stroke-width="{2 if dev.is_multihomed else 1.2}"{dash} '
             f'filter="url(#shadow)"/>',
             f'<use href="#ico-{dev.device_type}" '
             f'xlink:href="#ico-{dev.device_type}" '
             f'x="{_f((NODE_W - ICON_SIZE) / 2)}" y="{_f(ICON_TOP)}" '
             f'width="{_f(ICON_SIZE)}" height="{_f(ICON_SIZE)}"/>',
             f'<text class="t" x="{_f(NODE_W / 2)}" y="{_f(TITLE_Y)}" '
             f'text-anchor="middle">{escape(elide(title, TITLE_CHARS))}</text>',
             f'<text class="ip" x="{_f(NODE_W / 2)}" y="{_f(IP_Y)}" '
             f'text-anchor="middle">{escape(elide(ip_line, IP_CHARS))}</text>',
             f'<text class="dt" x="{_f(NODE_W / 2)}" y="{_f(DETAIL_Y)}" '
             f'text-anchor="middle">{escape(elide(detail, DETAIL_CHARS))}'
             f'</text>']
    left, right = card_badges(dev)
    for i, b in enumerate(left):
        bx, by = 6.0, 6.0 + i * (BADGE_H + 3)
        parts.append(_svg_badge(b, bx, by))
    for i, b in enumerate(right):
        bx, by = NODE_W - BADGE_W - 6, 6.0 + i * (BADGE_H + 3)
        parts.append(_svg_badge(b, bx, by))
    parts.append("</g>")
    return "".join(parts)


def _svg_badge(b, x: float, y: float) -> str:
    return (f'<g><title>{escape(b.tooltip or b.text)}</title>'
            f'<rect x="{_f(x)}" y="{_f(y)}" width="{_f(BADGE_W)}" '
            f'height="{_f(BADGE_H)}" rx="4" fill="{b.bg}"/>'
            f'<text class="bd" x="{_f(x + BADGE_W / 2)}" y="{_f(y + 10.2)}" '
            f'text-anchor="middle">{escape(b.text)}</text></g>')


def _svg_legend(sc: _Scene, height: float) -> str:
    if not (sc.types or sc.kinds):
        return ""
    per_row = max(1, int((sc.width - 2 * PAD) // LEGEND_ITEM_W))
    rows = -(-len(sc.types) // per_row) + -(-len(sc.kinds) // per_row)
    y = height - PAD / 2 - rows * LEGEND_ROW_H - 18
    out = ['<g id="legend">',
           f'<text x="{_f(PAD)}" y="{_f(y)}" style="font-size:12px;'
           'font-weight:700;fill:#2c3e50">Обозначения</text>']
    y += 12
    for i, t in enumerate(sc.types):
        col, row = i % per_row, i // per_row
        x = PAD + col * LEGEND_ITEM_W
        yy = y + row * LEGEND_ROW_H
        out.append(f'<use href="#ico-{t}" xlink:href="#ico-{t}" x="{_f(x)}" '
                   f'y="{_f(yy)}" width="18" height="18"/>'
                   f'<text class="lg" x="{_f(x + 24)}" y="{_f(yy + 13)}">'
                   f'{escape(DEVICE_TYPE_LABELS.get(t, t))}</text>')
    y += -(-len(sc.types) // per_row) * LEGEND_ROW_H
    for i, k in enumerate(sc.kinds):
        col, row = i % per_row, i // per_row
        x = PAD + col * LEGEND_ITEM_W
        yy = y + row * LEGEND_ROW_H + 9
        st = link_style(k)
        dash = (f' stroke-dasharray="{" ".join(_f(d) for d in st.dash)}"'
                if st.dash else "")
        out.append(f'<path d="M{_f(x)} {_f(yy)} h18" stroke="{st.color}" '
                   f'stroke-width="{_f(st.width)}"{dash}/>'
                   f'<text class="lg" x="{_f(x + 24)}" y="{_f(yy + 4)}">'
                   f'{escape(link_label(k))}</text>')
    out.append("</g>")
    return "".join(out)


def export_svg(topology: "NetworkTopology", path: str) -> None:
    _write_text(path, '<?xml version="1.0" encoding="UTF-8"?>\n'
                + render_svg(topology))


# ═══════════════════════════════════════════════════════════════════════════
# HTML (интерактивный, самодостаточный)
# ═══════════════════════════════════════════════════════════════════════════

def _device_json(topology: "NetworkTopology") -> list[dict]:
    neighbors: dict[str, list[str]] = {n: [] for n in topology.devices}
    for u, v, _d in topology.links:
        neighbors[u].append(v)
        neighbors[v].append(u)
    items = []
    for nid, dev in topology.devices.items():
        title, ip_line, detail = card_lines(dev)
        items.append({
            "id": nid,
            "name": dev.display_name(),
            "type": dev.device_type,
            "typeLabel": DEVICE_TYPE_LABELS.get(dev.device_type,
                                                dev.device_type),
            "confidence": dev.confidence,
            "ips": [] if dev.is_virtual else dev.all_ips(),
            "mac": dev.mac or "",
            "vendor": dev.vendor or "",
            "os": dev.os_name or "",
            "model": dev.model or "",
            "subnet": dev.subnet,
            "hops": dev.hops,
            "gateway": dev.is_gateway,
            "ports": dev.open_ports,
            "location": dev.location,
            "notes": dev.notes,
            "evidence": dev.evidence,
            "neighbors": sorted(
                {topology.devices[n].display_name() for n in neighbors[nid]}),
            "search": " ".join(filter(None, [
                title, ip_line, detail, dev.mac or "", dev.vendor or "",
                dev.os_name, dev.netbios_name, dev.subnet,
                " ".join(dev.all_ips())])).lower(),
        })
    return items


_HTML_TEMPLATE = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="__GENERATOR__">
<title>__TITLE__</title>
<style>
:root{--bg:#eef1f3;--panel:#ffffff;--text:#1c2833;--muted:#5d6d7e;
  --border:#d5d8dc;--accent:#2471a3;--hit:#f1c40f}
@media (prefers-color-scheme: dark){:root{--bg:#1b2026;--panel:#262c33;
  --text:#e5e8e8;--muted:#a6acaf;--border:#3d4650;--accent:#5dade2}}
*{box-sizing:border-box}
html,body{margin:0;height:100%;background:var(--bg);color:var(--text);
  font:14px/1.4 Segoe UI,Roboto,Helvetica,Arial,sans-serif}
#app{display:flex;flex-direction:column;height:100%}
header{display:flex;flex-wrap:wrap;gap:8px;align-items:center;
  padding:8px 12px;background:var(--panel);border-bottom:1px solid var(--border)}
header h1{font-size:15px;margin:0 12px 0 0;white-space:nowrap;overflow:hidden;
  text-overflow:ellipsis;max-width:40vw}
header input{flex:1 1 200px;min-width:140px;padding:6px 10px;border-radius:6px;
  border:1px solid var(--border);background:var(--bg);color:var(--text)}
button{padding:6px 10px;border-radius:6px;border:1px solid var(--border);
  background:var(--panel);color:var(--text);cursor:pointer}
button:hover{border-color:var(--accent)}
#count{color:var(--muted);font-size:12px;white-space:nowrap}
main{position:relative;flex:1 1 0;min-height:0;overflow:hidden}
#stage{position:absolute;top:0;right:0;bottom:0;left:0;touch-action:none;
  cursor:grab}
#stage.drag{cursor:grabbing}
#stage svg{width:100%;height:100%;display:block}
.node{cursor:pointer}
.node.hit .card{stroke:var(--hit);stroke-width:4}
.node.sel .card{stroke:var(--accent);stroke-width:4}
.dim{opacity:.18}
.hidden{display:none}
aside{position:absolute;top:10px;bottom:10px;right:10px;width:340px;
  max-width:calc(100% - 20px);background:var(--panel);border:1px solid var(--border);
  border-radius:10px;padding:14px 16px;overflow:auto;box-shadow:0 4px 18px #0003}
aside h2{font-size:16px;margin:0 28px 4px 0;word-break:break-word}
aside .close{position:absolute;top:8px;right:8px;border:none;font-size:18px}
aside dl{display:grid;grid-template-columns:auto 1fr;gap:4px 10px;margin:10px 0}
aside dt{color:var(--muted)}aside dd{margin:0;word-break:break-word}
aside ul{margin:4px 0 0 18px;padding:0;color:var(--muted);font-size:12px}
#legend{position:absolute;left:10px;bottom:10px;max-height:45%;overflow:auto;
  background:var(--panel);border:1px solid var(--border);border-radius:10px;
  padding:8px 10px;font-size:12px}
#legend label{display:flex;align-items:center;gap:6px;margin:2px 0;cursor:pointer}
#legend .sw{width:12px;height:12px;border-radius:3px;display:inline-block}
@media (max-width:640px){header h1{display:none}aside{top:auto;height:55%;width:auto;left:10px}}
</style>
</head>
<body>
<div id="app">
<header>
  <h1 title="__TITLE__">__TITLE__</h1>
  <input id="q" type="search" placeholder="Поиск: имя, IP, MAC, производитель, ОС…"
         aria-label="Поиск устройства">
  <span id="count"></span>
  <button id="fit" title="Вписать (F)">⊡ Вписать</button>
  <button id="zin" title="Увеличить (+)">＋</button>
  <button id="zout" title="Уменьшить (−)">－</button>
  <button id="legendBtn" title="Обозначения и фильтр">Фильтр</button>
  <button id="dl" title="Сохранить схему как SVG">SVG</button>
</header>
<main>
  <div id="stage">__SVG__</div>
  <div id="legend" class="hidden"></div>
  <aside id="info" class="hidden" aria-live="polite"></aside>
</main>
</div>
<script id="data" type="application/json">__DATA__</script>
<script>
(function(){
"use strict";
const DATA = JSON.parse(document.getElementById("data").textContent);
const COLORS = __COLORS__;
const byId = new Map(DATA.devices.map(d => [d.id, d]));
const svg = document.querySelector("#stage svg");
svg.removeAttribute("width"); svg.removeAttribute("height");
const full = svg.viewBox.baseVal;
const home = {x: full.x, y: full.y, w: full.width, h: full.height};
let vb = Object.assign({}, home);
function apply(){ svg.setAttribute("viewBox", vb.x+" "+vb.y+" "+vb.w+" "+vb.h); }
function fit(){ vb = Object.assign({}, home); apply(); }
function toSvg(cx, cy){
  const r = svg.getBoundingClientRect();
  const s = Math.max(vb.w / r.width, vb.h / r.height);
  const ox = (r.width * s - vb.w) / 2, oy = (r.height * s - vb.h) / 2;
  return {x: vb.x - ox + (cx - r.left) * s, y: vb.y - oy + (cy - r.top) * s, s: s};
}
function zoom(f, cx, cy){
  const r = svg.getBoundingClientRect();
  if (cx === undefined){ cx = r.left + r.width/2; cy = r.top + r.height/2; }
  const p = toSvg(cx, cy);
  const nw = Math.min(Math.max(vb.w / f, 40), home.w * 8);
  const k = nw / vb.w;
  vb.x = p.x - (p.x - vb.x) * k; vb.y = p.y - (p.y - vb.y) * k;
  vb.w = nw; vb.h = vb.h * k; apply();
}
const stage = document.getElementById("stage");
stage.addEventListener("wheel", e => { e.preventDefault();
  zoom(e.deltaY < 0 ? 1.15 : 1/1.15, e.clientX, e.clientY); }, {passive:false});
const pointers = new Map(); let last = null, pinch = 0, moved = false;
stage.addEventListener("pointerdown", e => {
  pointers.set(e.pointerId, {x:e.clientX, y:e.clientY}); moved = false;
  last = {x:e.clientX, y:e.clientY}; stage.classList.add("drag");
});
stage.addEventListener("pointermove", e => {
  if (!pointers.has(e.pointerId)) return;
  pointers.set(e.pointerId, {x:e.clientX, y:e.clientY});
  if (pointers.size === 2){
    const [a, b] = [...pointers.values()];
    const d = Math.hypot(a.x-b.x, a.y-b.y);
    if (pinch) zoom(d / pinch, (a.x+b.x)/2, (a.y+b.y)/2);
    pinch = d; moved = true; return;
  }
  const s = toSvg(0, 0).s;
  const dx = e.clientX - last.x, dy = e.clientY - last.y;
  if (Math.abs(dx) + Math.abs(dy) > 3) moved = true;
  if (moved){ vb.x -= dx * s; vb.y -= dy * s; apply();
    if (!stage.hasPointerCapture(e.pointerId)) stage.setPointerCapture(e.pointerId); }
  last = {x:e.clientX, y:e.clientY};
});
function up(e){ pointers.delete(e.pointerId); pinch = 0;
  if (!pointers.size) stage.classList.remove("drag"); }
stage.addEventListener("pointerup", up); stage.addEventListener("pointercancel", up);

const info = document.getElementById("info");
function esc(s){ return String(s).replace(/[&<>"]/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c])); }
function row(k, v){ return (v === null || v === undefined || v === "" ||
  (Array.isArray(v) && !v.length)) ? "" :
  "<dt>"+esc(k)+"</dt><dd>"+esc(Array.isArray(v) ? v.join(", ") : v)+"</dd>"; }
function select(id){
  document.querySelectorAll(".node.sel").forEach(n => n.classList.remove("sel"));
  const d = byId.get(id); if (!d){ info.classList.add("hidden"); return; }
  const el = document.getElementById("n-" + id); if (el) el.classList.add("sel");
  info.innerHTML = '<button class="close" title="Закрыть (Esc)">✕</button>' +
    "<h2>"+esc(d.name)+"</h2><div style='color:var(--muted)'>"+esc(d.typeLabel) +
    (d.confidence ? " · уверенность " + d.confidence + "%" : "") + "</div><dl>" +
    row("IP", d.ips) + row("MAC", d.mac) + row("Производитель", d.vendor) +
    row("ОС", d.os) + row("Модель", d.model) + row("Подсеть", d.subnet) +
    row("Шлюз", d.gateway ? "да" : "") + row("Хопов", d.hops) +
    row("Порты", d.ports) + row("Расположение", d.location) +
    row("Соседи", d.neighbors) + row("Заметки", d.notes) + "</dl>" +
    (d.evidence.length ? "<b>Почему такой тип</b><ul>" +
      d.evidence.map(e => "<li>"+esc(e)+"</li>").join("") + "</ul>" : "");
  info.classList.remove("hidden");
  info.querySelector(".close").onclick = () => select(null);
}
svg.addEventListener("click", e => {
  if (moved) return;
  const g = e.target.closest(".node"); select(g ? g.dataset.id : null);
});
function center(id){
  const el = document.getElementById("n-" + id); if (!el) return;
  const b = el.getBBox(), m = el.transform.baseVal.consolidate().matrix;
  const w = Math.max(b.width * 6, 700), h = w * (home.h / home.w);
  vb = {x: m.e + b.width/2 - w/2, y: m.f + b.height/2 - h/2, w: w, h: h}; apply();
}
const q = document.getElementById("q"), count = document.getElementById("count");
let hits = [];
function search(){
  const t = q.value.trim().toLowerCase();
  hits = [];
  document.querySelectorAll(".node").forEach(n => {
    const d = byId.get(n.dataset.id);
    const ok = t && d.search.includes(t);
    n.classList.toggle("hit", !!ok);
    n.classList.toggle("dim", !!t && !ok);
    if (ok) hits.push(d.id);
  });
  document.querySelectorAll(".edge").forEach(e => e.classList.toggle("dim", !!t));
  count.textContent = t ? "Найдено: " + hits.length : DATA.summary;
}
q.addEventListener("input", search);
q.addEventListener("keydown", e => { if (e.key === "Enter" && hits.length){
  const i = (hits.indexOf(info.dataset.cur) + 1) % hits.length;
  info.dataset.cur = hits[i]; center(hits[i]); select(hits[i]); } });

const legend = document.getElementById("legend");
const hiddenTypes = new Set();
function applyFilter(){
  const hiddenNodes = new Set();
  document.querySelectorAll(".node").forEach(n => {
    const h = hiddenTypes.has(n.dataset.type); n.classList.toggle("hidden", h);
    if (h) hiddenNodes.add(n.dataset.id); });
  document.querySelectorAll(".edge").forEach(e => e.classList.toggle("hidden",
    hiddenNodes.has(e.dataset.src) || hiddenNodes.has(e.dataset.dst)));
}
legend.innerHTML = "<b>Типы устройств</b>" + DATA.types.map(t =>
  '<label><input type="checkbox" checked data-t="'+esc(t.id)+'">' +
  '<span class="sw" style="background:'+COLORS[t.id]+'"></span>' +
  esc(t.label) + " (" + t.count + ")</label>").join("");
legend.addEventListener("change", e => { const t = e.target.dataset.t;
  if (e.target.checked) hiddenTypes.delete(t); else hiddenTypes.add(t); applyFilter(); });

document.getElementById("fit").onclick = fit;
document.getElementById("zin").onclick = () => zoom(1.3);
document.getElementById("zout").onclick = () => zoom(1/1.3);
document.getElementById("legendBtn").onclick = () => legend.classList.toggle("hidden");
document.getElementById("dl").onclick = () => {
  const clone = svg.cloneNode(true);
  clone.setAttribute("viewBox", home.x+" "+home.y+" "+home.w+" "+home.h);
  clone.setAttribute("width", home.w); clone.setAttribute("height", home.h);
  const blob = new Blob(['<?xml version="1.0" encoding="UTF-8"?>\\n' +
    new XMLSerializer().serializeToString(clone)], {type: "image/svg+xml"});
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
  a.download = (DATA.fileName || "topology") + ".svg"; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
};
document.addEventListener("keydown", e => {
  if (e.target === q) { if (e.key === "Escape"){ q.value = ""; search(); } return; }
  if (e.key === "Escape") select(null);
  else if (e.key === "f" || e.key === "F" || e.key === "0") fit();
  else if (e.key === "+" || e.key === "=") zoom(1.3);
  else if (e.key === "-") zoom(1/1.3);
  else if (e.key === "/"){ e.preventDefault(); q.focus(); }
});
search(); apply();
})();
</script>
</body>
</html>
"""


def render_html(topology: "NetworkTopology", file_name: str = "topology") -> str:
    svg = render_svg(topology, interactive=True)
    devices = _device_json(topology)
    counts: dict[str, int] = {}
    for d in topology.devices.values():
        counts[d.device_type] = counts.get(d.device_type, 0) + 1
    data = {
        "devices": devices,
        "types": [{"id": t, "label": DEVICE_TYPE_LABELS.get(t, t),
                   "count": counts[t]} for t in DEVICE_TYPES if t in counts],
        "summary": _subtitle(topology).split(" · ")[0] + " · связей: "
                   + str(len(topology.links)),
        "fileName": file_name,
    }
    colors = {t: type_color(t) for t in DEVICE_TYPES}
    title = html.escape(_title(topology))
    return (_HTML_TEMPLATE
            .replace("__TITLE__", title)
            .replace("__GENERATOR__", f"{APP_NAME} {APP_VERSION}")
            .replace("__COLORS__", _script_json(colors))
            .replace("__DATA__", _script_json(data))
            .replace("__SVG__", svg))


def _script_json(obj) -> str:
    """JSON, безопасный для вставки внутрь <script>."""
    return (json.dumps(obj, ensure_ascii=False)
            .replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("&", "\\u0026"))


def export_html(topology: "NetworkTopology", path: str) -> None:
    name = os.path.splitext(os.path.basename(path))[0] or "topology"
    _write_text(path, render_html(topology, name))


# ═══════════════════════════════════════════════════════════════════════════
# draw.io / diagrams.net
# ═══════════════════════════════════════════════════════════════════════════

def render_drawio(topology: "NetworkTopology") -> str:
    sc = _prepare(topology)
    icons = {t: base64.b64encode(icon_svg(t).encode()).decode() for t in sc.types}
    cells: list[str] = ['<mxCell id="0"/>', '<mxCell id="1" parent="0"/>']

    for i, z in enumerate(sc.zones):
        r, g, b = z.rgb
        style = (f"rounded=1;arcSize=3;whiteSpace=wrap;html=1;"
                 f"fillColor=#{r:02x}{g:02x}{b:02x};opacity=35;"
                 f"strokeColor=#{int(r * .6):02x}{int(g * .6):02x}"
                 f"{int(b * .6):02x};dashed=1;verticalAlign=top;align=left;"
                 f"spacingLeft=10;spacingTop=2;fontStyle=1;fontSize=12;"
                 f"textOpacity=100;container=0;")
        cells.append(
            f'<mxCell id="zone-{i}" value={_a(f"{z.cidr} · {z.count}")} '
            f'style={_a(style)} vertex="1" parent="1">'
            f'<mxGeometry x="{_f(z.x)}" y="{_f(z.y)}" width="{_f(z.w)}" '
            f'height="{_f(z.h)}" as="geometry"/></mxCell>')

    node_ids = {nid: f"node-{nid}" for nid, _x, _y in sc.nodes}
    for i, (u, v, kind, pts) in enumerate(sc.edges):
        st = link_style(kind)
        style = (f"endArrow=none;html=1;rounded=0;strokeColor={st.color};"
                 f"strokeWidth={_f(st.width)};")
        if st.dash:
            style += ("dashed=1;dashPattern="
                      + " ".join(_f(d) for d in st.dash) + ";")
        waypoints = "".join(f'<mxPoint x="{_f(x)}" y="{_f(y)}"/>'
                            for x, y in pts[1:-1])
        geom = ('<mxGeometry relative="1" as="geometry">'
                + (f'<Array as="points">{waypoints}</Array>' if waypoints else "")
                + "</mxGeometry>")
        cells.append(
            f'<mxCell id="edge-{i}" value="" style={_a(style)} edge="1" '
            f'parent="1" source="{node_ids[u]}" target="{node_ids[v]}">'
            f'{geom}</mxCell>')

    for nid, cx, cy in sc.nodes:
        dev = topology.devices[nid]
        title, ip_line, detail = card_lines(dev)
        label = (f"<b>{html.escape(elide(title, TITLE_CHARS + 4))}</b><br>"
                 f"{html.escape(ip_line)}<br>"
                 f'<font color="#7f8c8d" style="font-size:9px">'
                 f"{html.escape(elide(detail, DETAIL_CHARS + 6))}</font>")
        border = "#f39c12" if dev.is_multihomed else "#ccd1d1"
        style = (f"shape=label;rounded=1;arcSize=8;whiteSpace=wrap;html=1;"
                 f"fillColor=#ffffff;strokeColor={border};"
                 f"strokeWidth={2 if dev.is_multihomed else 1};"
                 f"image=data:image/svg+xml,{icons[dev.device_type]};"
                 f"imageWidth={int(ICON_SIZE)};imageHeight={int(ICON_SIZE)};"
                 f"imageAlign=center;imageVerticalAlign=top;"
                 f"spacingTop={int(ICON_TOP + ICON_SIZE)};verticalAlign=top;"
                 f"align=center;fontSize=10;fontColor=#1c2833;shadow=1;")
        if dev.is_virtual:
            style += "dashed=1;"
        props = {
            "label": label, "tooltip": device_tooltip(dev),
            "ip": ", ".join(dev.all_ips()), "mac": dev.mac or "",
            "vendor": dev.vendor or "", "os": dev.os_name,
            "type": DEVICE_TYPE_LABELS.get(dev.device_type, dev.device_type),
            "subnet": dev.subnet, "placeholders": "1",
        }
        attrs = " ".join(f"{k}={_a(v)}" for k, v in props.items())
        cells.append(
            f'<UserObject {attrs} id="{node_ids[nid]}">'
            f'<mxCell style={_a(style)} vertex="1" parent="1">'
            f'<mxGeometry x="{_f(cx - NODE_W / 2)}" y="{_f(cy - NODE_H / 2)}" '
            f'width="{_f(NODE_W)}" height="{_f(NODE_H)}" as="geometry"/>'
            f"</mxCell></UserObject>")

    title_style = ("text;html=1;align=left;verticalAlign=top;fontSize=18;"
                   "fontStyle=1;fontColor=#1b2631;")
    cells.append(
        f'<mxCell id="title" value={_a(html.escape(_title(topology)) + "<br>"
                                        "<font style=\"font-size:11px\" "
                                        "color=\"#5d6d7e\">"
                                        + html.escape(_subtitle(topology))
                                        + "</font>")} '
        f'style={_a(title_style)} vertex="1" parent="1">'
        f'<mxGeometry x="{_f(PAD)}" y="10" width="900" height="50" '
        f'as="geometry"/></mxCell>')

    stamp = datetime.now().astimezone().isoformat(timespec="seconds")
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<mxfile host="{APP_NAME}" modified="{stamp}" '
        f'agent="{APP_NAME} {APP_VERSION}" version="21.0.0" type="device">'
        f'<diagram id="topology" name="Топология">'
        f'<mxGraphModel dx="1200" dy="800" grid="1" gridSize="10" guides="1" '
        f'tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" '
        f'pageWidth="{int(sc.width)}" pageHeight="{int(sc.height)}" '
        f'math="0" shadow="0"><root>'
        + "".join(cells) +
        "</root></mxGraphModel></diagram></mxfile>\n")


def export_drawio(topology: "NetworkTopology", path: str) -> None:
    _write_text(path, render_drawio(topology))


# ═══════════════════════════════════════════════════════════════════════════
# GraphML (yEd + стандартные атрибуты для Gephi / Cytoscape / NetworkX)
# ═══════════════════════════════════════════════════════════════════════════

_GRAPHML_NODE_KEYS = [
    ("label", "string"), ("ip", "string"), ("all_ips", "string"),
    ("hostname", "string"), ("mac", "string"), ("vendor", "string"),
    ("type", "string"), ("type_label", "string"), ("os", "string"),
    ("subnet", "string"), ("multihomed", "boolean"), ("gateway", "boolean"),
    ("hops", "int"), ("open_ports", "string"), ("x", "double"),
    ("y", "double"), ("color", "string"),
]


def render_graphml(topology: "NetworkTopology") -> str:
    topology.place_missing()
    out = ['<?xml version="1.0" encoding="UTF-8" standalone="no"?>',
           '<graphml xmlns="http://graphml.graphdrawing.org/xmlns" '
           'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
           'xmlns:y="http://www.yworks.com/xml/graphml" '
           'xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns '
           'http://www.yworks.com/xml/schema/graphml/1.1/ygraphml.xsd">',
           '<key for="node" id="ng" yfiles.type="nodegraphics"/>',
           '<key for="edge" id="eg" yfiles.type="edgegraphics"/>']
    for name, typ in _GRAPHML_NODE_KEYS:
        out.append(f'<key attr.name="{name}" attr.type="{typ}" for="node" '
                   f'id="n_{name}"/>')
    out.append('<key attr.name="kind" attr.type="string" for="edge" id="e_kind"/>')
    out.append('<key attr.name="label" attr.type="string" for="edge" '
               'id="e_label"/>')
    out.append('<graph edgedefault="undirected" id="topology">')

    for nid, dev in topology.devices.items():
        x, y = dev.position
        title, ip_line, _detail = card_lines(dev)
        color = type_color(dev.device_type)
        values = {
            "label": title, "ip": dev.ip, "all_ips": ",".join(dev.all_ips()),
            "hostname": dev.hostname or "", "mac": dev.mac or "",
            "vendor": dev.vendor or "", "type": dev.device_type,
            "type_label": DEVICE_TYPE_LABELS.get(dev.device_type, ""),
            "os": dev.os_name, "subnet": dev.subnet,
            "multihomed": "true" if dev.is_multihomed else "false",
            "gateway": "true" if dev.is_gateway else "false",
            "hops": "" if dev.hops is None else str(dev.hops),
            "open_ports": ",".join(str(p) for p in dev.open_ports),
            "x": _f(x), "y": _f(y), "color": color,
        }
        out.append(f'<node id={_a(nid)}>')
        out.append(
            '<data key="ng"><y:ShapeNode>'
            f'<y:Geometry height="{_f(NODE_H * .6)}" width="{_f(NODE_W)}" '
            f'x="{_f(x - NODE_W / 2)}" y="{_f(y - NODE_H * .3)}"/>'
            f'<y:Fill color="{color}" transparent="false"/>'
            f'<y:BorderStyle color="#2c3e50" type="'
            f'{"dashed" if dev.is_virtual else "line"}" width="'
            f'{"2.0" if dev.is_multihomed else "1.0"}"/>'
            f'<y:NodeLabel alignment="center" fontSize="11" textColor="'
            f'{"#ffffff" if _dark(color) else "#000000"}" '
            f'modelName="internal" modelPosition="c">'
            f'{escape(title)}&#10;{escape(ip_line)}</y:NodeLabel>'
            '<y:Shape type="roundrectangle"/></y:ShapeNode></data>')
        for name, _typ in _GRAPHML_NODE_KEYS:
            if values[name] != "":
                out.append(f'<data key="n_{name}">{escape(values[name])}</data>')
        out.append("</node>")

    for i, (u, v, data) in enumerate(topology.links):
        kind = data.get("label", "")
        st = link_style(kind)
        pts = topology.edge_route(u, v)[1:-1]
        path = "".join(f'<y:Point x="{_f(x)}" y="{_f(y)}"/>' for x, y in pts)
        out.append(
            f'<edge id="e{i}" source={_a(u)} target={_a(v)}>'
            '<data key="eg"><y:PolyLineEdge>'
            f'<y:Path sx="0.0" sy="0.0" tx="0.0" ty="0.0">{path}</y:Path>'
            f'<y:LineStyle color="{st.color}" type="'
            f'{"dashed" if st.dash else "line"}" width="{_f(st.width)}"/>'
            '<y:Arrows source="none" target="none"/>'
            '</y:PolyLineEdge></data>'
            f'<data key="e_kind">{escape(kind)}</data>'
            f'<data key="e_label">{escape(link_label(kind))}</data></edge>')
    out.append("</graph></graphml>")
    return "\n".join(out)


def _dark(hex_color: str) -> bool:
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return 0.299 * r + 0.587 * g + 0.114 * b < 140


def export_graphml(topology: "NetworkTopology", path: str) -> None:
    _write_text(path, render_graphml(topology))
    logger.info("GraphML → %s", path)


# ═══════════════════════════════════════════════════════════════════════════
# CSV-инвентаризация
# ═══════════════════════════════════════════════════════════════════════════

CSV_COLUMNS = ["IP", "Все IP", "Имя", "NetBIOS", "MAC", "Производитель",
               "Тип", "Уверенность, %", "ОС", "Модель", "Подсеть", "Шлюз",
               "Хопов", "Открытые порты", "Соседи", "Расположение", "Заметки"]


def export_csv(topology: "NetworkTopology", path: str) -> None:
    rows = []
    devices = sorted((d for d in topology.devices.values() if not d.is_virtual),
                     key=lambda d: (d.subnet, _ip_key(d.ip)))
    for dev in devices:
        nbrs = sorted({topology.devices[n].display_name()
                       for n in topology.graph.neighbors(dev.node_id)})
        rows.append([
            dev.ip, ", ".join(dev.all_ips()), dev.hostname or "",
            dev.netbios_name, dev.mac or "", dev.vendor or "",
            DEVICE_TYPE_LABELS.get(dev.device_type, dev.device_type),
            dev.confidence or "", dev.os_name, dev.model, dev.subnet,
            "да" if dev.is_gateway else "",
            "" if dev.hops is None else dev.hops,
            ", ".join(str(p) for p in dev.open_ports), ", ".join(nbrs),
            dev.location, dev.notes,
        ])

    def write(f) -> None:
        w = csv.writer(f, delimiter=";", quoting=csv.QUOTE_MINIMAL)
        w.writerow(CSV_COLUMNS)
        w.writerows(rows)
    _atomic_write(path, write, encoding="utf-8-sig", newline="")


def _ip_key(ip: str) -> tuple:
    from model import ip_sort_key
    return ip_sort_key(ip)


# ═══════════════════════════════════════════════════════════════════════════
# Общий вход
# ═══════════════════════════════════════════════════════════════════════════

def export_json(topology: "NetworkTopology", path: str) -> None:
    topology.save_json(path)


EXPORTERS: dict[str, Callable[["NetworkTopology", str], None]] = {
    ".html":    export_html,
    ".htm":     export_html,
    ".svg":     export_svg,
    ".drawio":  export_drawio,
    ".graphml": export_graphml,
    ".csv":     export_csv,
    ".json":    export_json,
}


def export_topology(topology: "NetworkTopology", path: str) -> str:
    """Экспорт по расширению файла. Возвращает абсолютный путь."""
    ext = os.path.splitext(path)[1].lower()
    func = EXPORTERS.get(ext)
    if func is None:
        raise ValueError(f"Неподдерживаемый формат «{ext}». Доступно: "
                         + ", ".join(sorted(EXPORTERS)))
    func(topology, path)
    logger.info("Экспорт %s → %s", ext, path)
    return os.path.abspath(path)


def _write_text(path: str, text: str) -> None:
    _atomic_write(path, lambda f: f.write(text))


def _atomic_write(path: str, writer: Callable, encoding: str = "utf-8",
                  newline: str | None = None) -> None:
    path = os.fspath(path)
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".export-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline=newline) as f:
            writer(f)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
