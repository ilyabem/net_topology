"""
tests/test_v2.py — тесты версии 2: раскладка без наложений, вывод связей,
формат файла, OUI, определение ОС, экспорт, CLI и смоук-тест GUI.
Запуск: pytest tests/ -v
"""
import csv
import json
import os
import random
import re
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import networkx as nx
import pytest

from layout import (NODE_H, NODE_W, find_overlaps, reanchor_route)
from model import (Device, NetworkTopology, ScanResult, is_laa_mac)


# ════════════════════════════════════════════════════════════════════════
# Генератор тестовых сетей
# ════════════════════════════════════════════════════════════════════════

TYPES = ["windows_endpoint", "linux_server", "printer", "voip_phone",
         "unknown", "mobile_device", "ip_camera"]


def make_results(n_subnets=4, seed=1, max_hosts=90, with_path=True):
    rnd = random.Random(seed)
    results = []
    for s in range(n_subnets):
        devs = [Device(ip=f"10.{s}.0.1", device_type="router"),
                Device(ip=f"10.{s}.0.2", device_type="switch")]
        for i in range(3, 3 + rnd.randint(1, max_hosts)):
            devs.append(Device(ip=f"10.{s}.0.{i}",
                               device_type=rnd.choice(TYPES)))
        path = ["192.168.0.1", None, f"172.16.0.{s}"] if (with_path and s) \
            else []
        results.append(ScanResult(subnet=f"10.{s}.0.0/24", devices=devs,
                                  gateway_ip=f"10.{s}.0.1", path=path))
    return results


def build(mode="tree", **kw):
    topo = NetworkTopology()
    topo.build_from_results(make_results(**kw), layout_mode=mode)
    return topo


def positions(topo):
    return {n: d.position for n, d in topo.devices.items()}


def route_hits(topo):
    """Сколько раз ортогональные отрезки связей проходят сквозь чужие карточки."""
    pos = positions(topo)
    hits = 0
    for u, v, _ in topo.links:
        pts = topo.edge_route(u, v)
        for (x1, y1), (x2, y2) in zip(pts, pts[1:]):
            for n, (cx, cy) in pos.items():
                if n in (u, v):
                    continue
                left, right = cx - NODE_W / 2, cx + NODE_W / 2
                top, bottom = cy - NODE_H / 2, cy + NODE_H / 2
                if x1 == x2 and left < x1 < right and \
                        min(y1, y2) < bottom and max(y1, y2) > top:
                    hits += 1
                elif y1 == y2 and top < y1 < bottom and \
                        min(x1, x2) < right and max(x1, x2) > left:
                    hits += 1
    return hits


# ════════════════════════════════════════════════════════════════════════
# Раскладка
# ════════════════════════════════════════════════════════════════════════

class TestLayout:
    @pytest.mark.parametrize("mode", ["tree", "tree-lr", "organic"])
    @pytest.mark.parametrize("seed", [1, 2, 3])
    def test_no_overlaps(self, mode, seed):
        topo = build(mode, seed=seed)
        assert all(d.position for d in topo.devices.values())
        assert find_overlaps(positions(topo)) == []

    @pytest.mark.parametrize("mode", ["tree", "tree-lr"])
    def test_routes_do_not_cross_cards(self, mode):
        topo = build(mode, seed=5)
        assert route_hits(topo) == 0

    def test_routes_orthogonal_in_tree(self):
        topo = build("tree", seed=7)
        for u, v, _ in topo.links:
            pts = topo.edge_route(u, v)
            for (x1, y1), (x2, y2) in zip(pts, pts[1:]):
                assert x1 == x2 or y1 == y2

    def test_large_flat_network(self):
        topo = NetworkTopology()
        devs = [Device(ip="10.9.0.1", device_type="router")] + \
            [Device(ip=f"10.9.{i // 250}.{i % 250 + 2}",
                    device_type="windows_endpoint") for i in range(600)]
        topo.build_from_results([ScanResult(subnet="10.9.0.0/22",
                                            devices=devs,
                                            gateway_ip="10.9.0.1")])
        assert find_overlaps(positions(topo)) == []
        assert route_hits(topo) == 0
        xs = [p[0] for p in positions(topo).values()]
        ys = [p[1] for p in positions(topo).values()]
        aspect = (max(xs) - min(xs)) / max(1, max(ys) - min(ys))
        assert 0.4 < aspect < 4, "блок листьев должен быть близок к экрану"

    def test_isolated_nodes_no_overlap(self):
        topo = NetworkTopology()
        for i in range(30):
            topo.add_device(Device(ip=f"1.1.1.{i}", node_id=f"n{i}"))
        topo.apply_layout("tree")
        assert find_overlaps(positions(topo)) == []

    def test_single_node(self):
        topo = NetworkTopology()
        topo.add_device(Device(ip="1.1.1.1"))
        for mode in ("tree", "tree-lr", "organic"):
            topo.apply_layout(mode)
            assert list(topo.devices.values())[0].position is not None

    def test_root_is_upstream_router(self):
        topo = build("tree", n_subnets=3, seed=4)
        y_by_ip = {d.ip: d.position[1] for d in topo.devices.values()}
        assert y_by_ip["192.168.0.1"] == min(y_by_ip.values())

    def test_layout_deterministic(self):
        a, b = build("tree", seed=9), build("tree", seed=9)
        pa = sorted((d.ip, d.position) for d in a.devices.values())
        pb = sorted((d.ip, d.position) for d in b.devices.values())
        assert pa == pb


class TestRoutesAfterDrag:
    def test_route_kept_without_move(self):
        topo = build("tree", n_subnets=1, seed=2)
        u, v, _ = next((u, v, d) for u, v, d in topo.links
                       if len(topo.edge_route(u, v)) > 2)
        assert len(topo.edge_route(u, v)) > 2

    @pytest.mark.parametrize("mode", ["tree", "tree-lr"])
    def test_moved_node_reconnects_orthogonally(self, mode):
        topo = build(mode, n_subnets=1, seed=2)
        gw = topo.get_by_ip("10.0.0.1")
        x, y = gw.position
        gw.position = (x + 333, y + 7)
        for nb in topo.graph.neighbors(gw.node_id):
            pts = topo.edge_route(gw.node_id, nb)
            assert len(pts) >= 3
            for (x1, y1), (x2, y2) in zip(pts, pts[1:]):
                assert abs(x1 - x2) < 1e-6 or abs(y1 - y2) < 1e-6

    @pytest.mark.parametrize("mode", ["tree", "tree-lr"])
    def test_links_without_route_are_orthogonal(self, mode):
        """После объединения узлов перенесённые связи не становятся диагоналями."""
        topo = build(mode, n_subnets=1, seed=2)
        gw, sw = topo.get_by_ip("10.0.0.1"), topo.get_by_ip("10.0.0.2")
        topo.merge_devices(gw.node_id, sw.node_id)
        for nb in topo.graph.neighbors(gw.node_id):
            pts = topo.edge_route(gw.node_id, nb)
            for (x1, y1), (x2, y2) in zip(pts, pts[1:]):
                assert abs(x1 - x2) < 1e-6 or abs(y1 - y2) < 1e-6
        # Сетка бывших потомков коммутатора: линии идут по зазорам
        assert route_hits(topo) == 0

    def test_reanchor_two_point_route(self):
        pts = reanchor_route([(0, 52), (0, 152)], (200, 0), None)
        assert pts[0] == (200, 52) and pts[-1] == (0, 152)
        assert all(a[0] == b[0] or a[1] == b[1] for a, b in zip(pts, pts[1:]))

    def test_reanchor_non_tree_route(self):
        assert reanchor_route([(0, 0), (10, 10)], (5, 5), None) is None


# ════════════════════════════════════════════════════════════════════════
# Зоны подсетей
# ════════════════════════════════════════════════════════════════════════

class TestZones:
    @pytest.mark.parametrize("mode", ["tree", "tree-lr"])
    def test_zones_do_not_overlap(self, mode):
        from visual import zone_members, zone_rect
        topo = build(mode, n_subnets=5, seed=11)
        rects = []
        for cidr, nids in zone_members(topo).items():
            rects.append(zone_rect([topo.devices[n].position for n in nids]))
        for i, (x1, y1, w1, h1) in enumerate(rects):
            for x2, y2, w2, h2 in rects[i + 1:]:
                assert x1 + w1 <= x2 or x2 + w2 <= x1 or \
                    y1 + h1 <= y2 or y2 + h2 <= y1

    def test_border_router_excluded_from_zone(self):
        from visual import zone_members
        topo = build("tree", n_subnets=2, seed=3)
        gw = topo.get_by_ip("10.1.0.1")
        assert gw.node_id not in zone_members(topo)["10.1.0.0/24"]


# ════════════════════════════════════════════════════════════════════════
# Построение связей
# ════════════════════════════════════════════════════════════════════════

class TestInferLinks:
    def test_switch_under_gateway_and_endpoints_under_switch(self):
        topo = NetworkTopology()
        topo.build_from_results([ScanResult(subnet="10.0.0.0/24", devices=[
            Device(ip="10.0.0.1", device_type="router", node_id="gw"),
            Device(ip="10.0.0.2", device_type="switch", node_id="sw"),
            Device(ip="10.0.0.10", device_type="windows_endpoint", node_id="pc"),
            Device(ip="10.0.0.11", device_type="printer", node_id="pr"),
        ], gateway_ip="10.0.0.1")])
        g = topo.graph
        assert g.has_edge("gw", "sw")
        assert g.has_edge("sw", "pc") and g.has_edge("sw", "pr")
        assert not g.has_edge("gw", "pc")

    def test_no_star_over_whole_network(self):
        topo = build("tree", n_subnets=3, seed=2)
        gw0 = topo.get_by_ip("10.0.0.1")
        foreign = [n for n in topo.graph.neighbors(gw0.node_id)
                   if topo.devices[n].subnet.startswith("10.2.")]
        assert foreign == []

    def test_segment_created_without_gateway(self):
        topo = NetworkTopology()
        topo.build_from_results([ScanResult(subnet="10.5.0.0/24", devices=[
            Device(ip=f"10.5.0.{i}", device_type="windows_endpoint")
            for i in range(10, 15)])])
        segs = [d for d in topo.devices.values() if d.is_virtual]
        assert len(segs) == 1
        assert topo.graph.degree(segs[0].node_id) == 5

    def test_path_chain(self):
        topo = NetworkTopology()
        topo.build_from_results([ScanResult(
            subnet="10.7.0.0/24",
            devices=[Device(ip="10.7.0.1", device_type="router"),
                     Device(ip="10.7.0.5", device_type="linux_server")],
            gateway_ip="10.7.0.1", path=["192.168.1.1", "172.16.0.1"])])
        a = topo.get_by_ip("192.168.1.1")
        b = topo.get_by_ip("172.16.0.1")
        gw = topo.get_by_ip("10.7.0.1")
        assert topo.graph.has_edge(a.node_id, b.node_id)
        assert topo.graph.has_edge(b.node_id, gw.node_id)
        assert a.is_gateway and b.device_type == "router"

    def test_confirmed_link_wins_over_inferred(self):
        topo = NetworkTopology()
        topo.add_device(Device(ip="1.1.1.1", node_id="a"))
        topo.add_device(Device(ip="1.1.1.2", node_id="b"))
        topo.add_link("a", "b", "inferred")
        topo.add_link("a", "b", "lldp", local_port="Gi0/1")
        data = topo.graph.edges["a", "b"]
        assert data["label"] == "lldp" and data["local_port"] == "Gi0/1"
        topo.add_link("a", "b", "inferred")
        assert topo.graph.edges["a", "b"]["label"] == "lldp"

    def test_legacy_arp_table(self):
        topo = NetworkTopology()
        topo.build_from_hosts(
            [Device(ip="10.0.0.1", node_id="g"),
             Device(ip="10.0.0.9", node_id="h")],
            {"10.0.0.1": [("10.0.0.9", "")]}, subnet="10.0.0.0/24")
        assert topo.graph.edges["g", "h"]["label"] == "ARP"


class TestMerge:
    def test_proxy_arp_not_merged(self):
        topo = NetworkTopology()
        for i in range(6):
            topo.add_device(Device(ip=f"10.0.0.{i + 10}", mac="00:11:22:33:44:55",
                                   subnet="10.0.0.0/24"))
        assert topo.merge_by_mac() == 0
        assert len(topo.devices) == 6
        assert all("proxy-ARP" in d.notes for d in topo.devices.values())

    def test_shared_ip_merge(self):
        topo = NetworkTopology()
        router = Device(ip="10.0.0.1", device_type="router", node_id="r")
        router.add_interface("10.1.0.1", "10.1.0.0/24")
        other = Device(ip="10.1.0.1", node_id="o", hostname="alias")
        topo.add_device(other)
        topo.add_device(router)
        assert topo.merge_shared_ips() == 1
        assert list(topo.devices) == ["r"]
        assert topo.devices["r"].hostname == "alias"
        assert topo.devices["r"].is_multihomed

    def test_split_primary_ip(self):
        topo = NetworkTopology()
        dev = Device(ip="10.0.0.1", node_id="r")
        dev.add_interface("10.1.0.1")
        topo.add_device(dev)
        new_id = topo.split_device("r", "10.0.0.1")
        assert new_id and dev.ip == "10.1.0.1"
        assert topo.get_by_ip("10.0.0.1").node_id == new_id


# ════════════════════════════════════════════════════════════════════════
# Формат файла
# ════════════════════════════════════════════════════════════════════════

class TestFileFormat:
    def test_v2_roundtrip_with_routes(self, tmp_path):
        topo = build("tree", n_subnets=2, seed=8)
        topo.devices[next(iter(topo.devices))].services = {22: "ssh"}
        path = tmp_path / "t.json"
        topo.save_json(str(path))
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["format"] == "net-topology" and data["version"] == 2
        t2 = NetworkTopology()
        t2.load_json(str(path))
        assert len(t2.devices) == len(topo.devices)
        assert len(t2.links) == len(topo.links)
        for u, v, _ in topo.links:
            assert t2.edge_route(u, v) == topo.edge_route(u, v)
        first = next(iter(t2.devices.values()))
        assert first.services == {22: "ssh"}

    def test_v1_file_loads(self, tmp_path):
        v1 = {"devices": {"a1": {"ip": "192.168.1.1", "mac": None,
                                 "hostname": "gw", "vendor": None,
                                 "device_type": "router", "open_ports": [80],
                                 "ttl": None, "snmp_info": {}, "node_id": "a1",
                                 "position": [10, 20], "notes": "",
                                 "subnet": "192.168.1.0/24",
                                 "interfaces": [{"ip": "192.168.1.1",
                                                 "subnet": "192.168.1.0/24",
                                                 "iface_name": ""}],
                                 "is_multihomed": False},
                          "b2": {"ip": "192.168.1.5", "node_id": "b2",
                                 "unknown_future_field": 1}},
              "links": [{"src": "a1", "dst": "b2", "label": "ARP"},
                        {"src": "a1", "dst": "zz", "label": "bad"}]}
        p = tmp_path / "v1.json"
        p.write_text(json.dumps(v1), encoding="utf-8")
        topo = NetworkTopology()
        topo.load_json(str(p))
        assert set(topo.devices) == {"a1", "b2"}
        assert topo.devices["a1"].position == (10.0, 20.0)
        assert topo.devices["b2"].position is not None   # раскладка достроена
        assert topo.graph.has_edge("a1", "b2")

    def test_not_a_topology(self, tmp_path):
        p = tmp_path / "x.json"
        p.write_text("[1, 2, 3]", encoding="utf-8")
        with pytest.raises(ValueError):
            NetworkTopology().load_json(str(p))

    def test_atomic_save_keeps_old_file_on_error(self, tmp_path, monkeypatch):
        topo = build("tree", n_subnets=1, seed=1)
        p = tmp_path / "t.json"
        topo.save_json(str(p))
        before = p.read_text(encoding="utf-8")

        def boom(*a, **k):
            raise OSError("disk full")
        monkeypatch.setattr(json, "dump", boom)
        with pytest.raises(OSError):
            topo.save_json(str(p))
        assert p.read_text(encoding="utf-8") == before
        assert [f.name for f in tmp_path.iterdir()] == ["t.json"]


# ════════════════════════════════════════════════════════════════════════
# OUI
# ════════════════════════════════════════════════════════════════════════

class TestOUIParsing:
    MANUF = ("# comment\n"
             "00:1B:C5         \tIEEERegist\tIEEE Registration Authority\n"
             "00:1B:C5:00:00/36\tConverging\tConverging Systems Inc.\n"
             "00:55:DA:A0:00:00/28\tTest28\tTwenty Eight Ltd\n"
             "44:19:B6\tHikvision\tHangzhou Hikvision Digital Technology Co.,Ltd.\n")

    def _db(self):
        from oui_db import OUIDatabase, parse_manuf
        db = OUIDatabase()
        db._db = parse_manuf(self.MANUF)
        db._loaded = True
        return db

    def test_mask_keys(self):
        from oui_db import parse_manuf
        keys = set(parse_manuf(self.MANUF))
        assert keys == {"001BC5", "001BC5000", "0055DAA", "4419B6"}

    def test_ma_s_more_specific(self):
        db = self._db()
        assert db.lookup("00:1B:C5:00:00:42") == "Converging Systems Inc."
        assert db.lookup("00:1B:C5:FF:00:42") == "IEEE Registration Authority"
        assert db.lookup("00:55:DA:A1:23:45") == "Twenty Eight Ltd"

    def test_camera_vendor(self):
        from oui_db import vendor_to_device_type
        db = self._db()
        assert vendor_to_device_type(db.lookup("44:19:B6:01:02:03"))[0] == \
            "ip_camera"

    def test_word_boundaries(self):
        from oui_db import vendor_to_device_type
        assert vendor_to_device_type("Shpe Industries") is None
        assert vendor_to_device_type("Polytechnic Inc") is None
        assert vendor_to_device_type("HP Inc.")[0] == "windows_endpoint"

    def test_short_vendor(self):
        from oui_db import short_vendor
        assert short_vendor("Cisco Systems, Inc") == "Cisco Systems"
        assert short_vendor("") == ""

    def test_url_is_current(self):
        import oui_db
        assert "gitlab.com" not in oui_db.WIRESHARK_URL


# ════════════════════════════════════════════════════════════════════════
# Классификация и ОС
# ════════════════════════════════════════════════════════════════════════

class TestAnalyzerV2:
    def _enrich(self, **kw):
        from analyzer import DeviceAnalyzer
        dev = Device(**kw)
        DeviceAnalyzer(use_oui_db=False).enrich(dev)
        return dev

    def test_windows_workstation(self):
        d = self._enrich(ip="10.0.0.5", hostname="DESKTOP-AB12CD3", ttl=128,
                         open_ports=[135, 445, 3389])
        assert d.device_type == "windows_endpoint"
        assert d.os_family == "windows" and d.confidence > 50
        assert d.evidence

    def test_domain_controller(self):
        d = self._enrich(ip="10.0.0.6", hostname="WIN-3K8L2MQ9PA", ttl=128,
                         open_ports=[53, 88, 389, 445])
        assert d.device_type == "windows_server"
        assert d.os_name == "Windows Server"

    def test_iphone_is_mobile_not_voip(self):
        d = self._enrich(ip="10.0.0.7", hostname="ivan-iphone", ttl=64)
        assert d.device_type == "mobile_device"
        assert d.os_family == "ios"

    def test_mikrotik(self):
        d = self._enrich(ip="10.0.0.9", ttl=253, open_ports=[22, 8291])
        assert d.device_type == "router"
        assert d.os_name == "MikroTik RouterOS"
        assert d.hops == 2

    def test_camera_by_rtsp(self):
        d = self._enrich(ip="10.0.0.10", hostname="cam-entrance",
                         open_ports=[80, 554])
        assert d.device_type == "ip_camera"

    def test_short_hostname_token_not_substring(self):
        d = self._enrich(ip="10.0.0.11", hostname="gwen-laptop", ttl=128)
        assert d.device_type != "router"

    def test_sysdescr_os(self):
        d = self._enrich(ip="10.0.0.12", snmp_info={
            "1.3.6.1.2.1.1.1.0": "Cisco IOS Software, C2960 Software"})
        assert d.os_name == "Cisco IOS"

    def test_hops_estimate(self):
        from analyzer import estimate_hops
        assert [estimate_hops(t) for t in (64, 61, 128, 120, 255, 250)] == \
            [0, 3, 0, 8, 0, 5]
        assert estimate_hops(None) is None

    @pytest.mark.skipif(sys.version_info >= (3, 12),
                        reason="pysnmp 4.4.12 ставится только на Python <= 3.11")
    def test_snmp_backend_loads_with_pinned_pysnmp(self):
        """pysnmp 4.4.12 + pyasn1 >= 0.6.1 молча отключали SNMP."""
        pytest.importorskip("pysnmp")
        import analyzer
        assert analyzer.SNMP_AVAILABLE
        assert analyzer._snmp_backend in ("classic-4x", "lextudio-sync",
                                          "netsnmp-cli")

    def test_laa_ignored_when_vendor_known(self):
        from analyzer import DeviceAnalyzer
        from oui_db import OUIDatabase, parse_manuf
        db = OUIDatabase()
        db._db = parse_manuf("FE:ED:CA\tFortinet\tFortinet Inc.\n")
        db._loaded = True
        a = DeviceAnalyzer(use_oui_db=False)
        a.use_oui_db, a._oui = True, db
        dev = Device(ip="10.0.0.2", mac="FE:ED:CA:11:22:33")
        assert is_laa_mac(dev.mac)
        a.enrich(dev)
        assert dev.device_type == "firewall"
        assert not any("LAA" in e for e in dev.evidence)


# ════════════════════════════════════════════════════════════════════════
# Экспорт
# ════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def export_topo():
    rnd = random.Random(3)
    res = []
    for s in range(2):
        devs = [Device(ip=f"10.{s}.0.1", device_type="router",
                       hostname=f"gw{s}", vendor="Cisco Systems, Inc",
                       open_ports=[22, 161], is_gateway=True)]
        for i in range(3, 20):
            devs.append(Device(ip=f"10.{s}.0.{i}",
                               device_type=rnd.choice(TYPES),
                               hostname=f"pc-{i}<&\"'>", mac=f"00:11:22:33:{s:02x}:{i:02x}"))
        res.append(ScanResult(subnet=f"10.{s}.0.0/24", devices=devs,
                              gateway_ip=f"10.{s}.0.1"))
    topo = NetworkTopology()
    topo.build_from_results(res)
    return topo


class TestExporters:
    def test_svg_valid(self, export_topo, tmp_path):
        from exporters import export_topology
        p = export_topology(export_topo, str(tmp_path / "t.svg"))
        root = ET.parse(p).getroot()
        assert root.tag.endswith("svg")
        assert len(root.findall(".//{http://www.w3.org/2000/svg}g[@class='node']")) \
            == len(export_topo.devices)

    def test_html_self_contained(self, export_topo, tmp_path):
        from exporters import export_topology
        p = export_topology(export_topo, str(tmp_path / "t.html"))
        text = open(p, encoding="utf-8").read()
        assert "http://" not in re.sub(r'xmlns(:\w+)?="[^"]+"', "", text) \
            .replace("http://graphml", "")
        data = json.loads(re.search(
            r'<script id="data" type="application/json">(.*?)</script>',
            text, re.S).group(1))
        assert len(data["devices"]) == len(export_topo.devices)
        ET.fromstring(re.search(r"(<svg.*?</svg>)", text, re.S).group(1))
        assert "</script><" not in json.dumps(data)

    def test_drawio_valid(self, export_topo, tmp_path):
        from exporters import export_topology
        p = export_topology(export_topo, str(tmp_path / "t.drawio"))
        root = ET.parse(p).getroot()
        assert root.tag == "mxfile"
        objs = root.findall(".//UserObject")
        assert len(objs) == len(export_topo.devices)
        edges = [c for c in root.iter("mxCell") if c.get("edge") == "1"]
        ids = {o.get("id") for o in objs}
        assert len(edges) == len(export_topo.links)
        assert all(e.get("source") in ids and e.get("target") in ids
                   for e in edges)

    def test_graphml_readable(self, export_topo, tmp_path):
        from exporters import export_topology
        p = export_topology(export_topo, str(tmp_path / "t.graphml"))
        g = nx.read_graphml(p)
        assert g.number_of_nodes() == len(export_topo.devices)
        assert g.number_of_edges() == len(export_topo.links)

    def test_csv(self, export_topo, tmp_path):
        from exporters import export_topology
        p = export_topology(export_topo, str(tmp_path / "t.csv"))
        with open(p, encoding="utf-8-sig", newline="") as f:
            rows = list(csv.reader(f, delimiter=";"))
        assert rows[0][0] == "IP"
        assert len(rows) - 1 == sum(1 for d in export_topo.devices.values()
                                    if not d.is_virtual)

    def test_csv_formula_injection_escaped(self, tmp_path):
        from exporters import export_topology
        topo = NetworkTopology()
        topo.add_device(Device(ip="10.0.0.5", hostname="=cmd|' /C calc'!A0"))
        p = export_topology(topo, str(tmp_path / "t.csv"))
        with open(p, encoding="utf-8-sig", newline="") as f:
            rows = list(csv.reader(f, delimiter=";"))
        assert rows[1][2] == "'=cmd|' /C calc'!A0"

    def test_unknown_format(self, export_topo, tmp_path):
        from exporters import export_topology
        with pytest.raises(ValueError):
            export_topology(export_topo, str(tmp_path / "t.xyz"))

    def test_export_assigns_layout(self, tmp_path):
        from exporters import export_topology
        topo = NetworkTopology()
        topo.add_device(Device(ip="1.1.1.1"))
        export_topology(topo, str(tmp_path / "t.svg"))
        assert next(iter(topo.devices.values())).position is not None


# ════════════════════════════════════════════════════════════════════════
# Excel: список найденных IP-адресов
# ════════════════════════════════════════════════════════════════════════

class TestXlsxIpList:
    @pytest.fixture()
    def topo(self):
        from analyzer import DeviceAnalyzer
        a = DeviceAnalyzer(use_oui_db=False)
        devs = [
            Device(ip="10.0.0.1", hostname="gw", device_type="router",
                   open_ports=[22, 161]),
            Device(ip="10.0.0.10", hostname="DESKTOP-AB12CD3", ttl=128,
                   open_ports=[135, 445, 3389]),
            Device(ip="10.0.0.9", hostname="prn-2", open_ports=[9100]),
            Device(ip="10.0.0.20", hostname='=HYPERLINK("http://x","y")'),
        ]
        for d in devs[1:]:
            a.enrich(d)
        devs[0].add_interface("172.16.0.1", "172.16.0.0/24")
        devs.append(Device(ip="10.0.0.30", device_type="windows_endpoint"))
        topo = NetworkTopology()
        topo.build_from_results([
            ScanResult(subnet="10.0.0.0/24", devices=devs,
                       gateway_ip="10.0.0.1"),
            # подсеть без шлюза → появится виртуальный «сегмент»
            ScanResult(subnet="10.9.0.0/24", devices=[
                Device(ip="10.9.0.5"), Device(ip="10.9.0.6")])])
        return topo

    def _load(self, topo, tmp_path):
        openpyxl = pytest.importorskip("openpyxl")
        from exporters import export_topology
        p = export_topology(topo, str(tmp_path / "ips.xlsx"))
        return p, openpyxl.load_workbook(p)

    def test_one_row_per_ip_sorted(self, topo, tmp_path):
        _p, wb = self._load(topo, tmp_path)
        ws = wb["IP-адреса"]
        ips = [r[0] for r in ws.iter_rows(min_row=2, values_only=True)]
        real_ips = sorted((ip for d in topo.devices.values()
                           if not d.is_virtual for ip in d.all_ips()),
                          key=lambda ip: tuple(int(x) for x in ip.split(".")))
        assert ips == real_ips                      # без сегментов, по числу
        assert ips.index("10.0.0.9") < ips.index("10.0.0.10")
        assert "172.16.0.1" in ips                  # второй интерфейс шлюза

    def test_columns_and_layout(self, topo, tmp_path):
        from exporters import XLSX_COLUMNS
        _p, wb = self._load(topo, tmp_path)
        ws = wb["IP-адреса"]
        header = [c.value for c in ws[1]]
        assert header == [t for t, _w in XLSX_COLUMNS]
        for col in ("IP", "ОС", "Предполагаемый тип", "Почему такой тип",
                    "Уверенность, %", "MAC", "Производитель",
                    "Открытые порты", "Подсеть"):
            assert col in header
        assert ws.freeze_panes == "B2"
        assert ws.auto_filter.ref.startswith("A1:")
        assert wb.sheetnames == ["IP-адреса", "Сводка"]

    def test_values_human_readable(self, topo, tmp_path):
        _p, wb = self._load(topo, tmp_path)
        rows = {r[0]: r for r in wb["IP-адреса"].iter_rows(min_row=2,
                                                            values_only=True)}
        pc = rows["10.0.0.10"]
        assert pc[3] == "Windows" and pc[4] == "Windows ПК"
        assert isinstance(pc[5], int) and pc[5] > 0
        assert "windows_endpoint" not in pc[6] and "(+" not in pc[6]
        assert "3389 RDP" in pc[9]
        printer = rows["10.0.0.9"]
        assert printer[4] == "Принтер/МФУ" and "9100" in printer[6]
        assert rows["10.0.0.1"][12] == "172.16.0.1"     # другие IP устройства
        assert rows["10.0.0.30"][3] == "не определена"

    def test_formula_injection_stored_as_text(self, topo, tmp_path):
        import zipfile
        p, wb = self._load(topo, tmp_path)
        cell = next(c for c in wb["IP-адреса"]["C"]
                    if str(c.value).startswith("=HYPERLINK"))
        assert cell.data_type == "s"
        for name in zipfile.ZipFile(p).namelist():
            if name.startswith("xl/worksheets/"):
                assert b"<f>" not in zipfile.ZipFile(p).read(name)

    def test_summary_sheet(self, topo, tmp_path):
        _p, wb = self._load(topo, tmp_path)
        values = {r[0]: r[1] for r in wb["Сводка"].iter_rows(values_only=True)
                  if r[0]}
        # 5 устройств подсети 10.0.0.0/24 (у шлюза 2 IP) + 2 в 10.9.0.0/24
        assert values["Найдено IP-адресов"] == 8
        assert values["Из них с несколькими IP"] == 1

    def test_listed_in_gui_formats(self):
        from exporters import EXPORT_FORMATS, EXPORTERS
        assert ".xlsx" in EXPORT_FORMATS and ".xlsx" in EXPORTERS

    def test_humanize_evidence(self):
        from exporters import humanize_evidence
        dev = Device(ip="1.1.1.1", device_type="printer", evidence=[
            "Порт 80 (HTTP) → linux_server (+2)",
            "Порт 9100 (JetDirect) однозначно → printer (+15)",
            "ОС: TTL 64 → Linux (+1.5)"])
        assert humanize_evidence(dev) == \
            "Порт 9100 (JetDirect) однозначно → Принтер/МФУ"


# ════════════════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════════════════

class TestCLI:
    def test_load_and_export(self, tmp_path, monkeypatch, capsys):
        import net_topology
        topo = build("tree", n_subnets=1, seed=1)
        src = tmp_path / "in.json"
        topo.save_json(str(src))
        out_html = tmp_path / "o.html"
        out_drawio = tmp_path / "o.drawio"
        out_xlsx = tmp_path / "o.xlsx"
        monkeypatch.setattr(sys, "argv", [
            "net_topology.py", "--load", str(src), "--no-gui",
            "--layout", "tree-lr", "--export", str(out_html),
            "--export", str(out_drawio), "--export", str(out_xlsx)])
        net_topology.main()
        assert out_html.exists() and out_drawio.exists()
        assert out_xlsx.exists() and out_xlsx.read_bytes()[:2] == b"PK"
        assert "ОБНАРУЖЕННЫЕ УСТРОЙСТВА" in capsys.readouterr().out


# ════════════════════════════════════════════════════════════════════════
# GUI (смоук-тест в offscreen-режиме)
# ════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def qapp():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    qtw = pytest.importorskip("PyQt5.QtWidgets")
    app = qtw.QApplication.instance() or qtw.QApplication([])
    yield app


class TestGUI:
    def _window(self, qapp, tmp_path, monkeypatch):
        import importlib
        sys.modules.pop("gui", None)       # другие тесты подменяют gui
        gui = importlib.import_module("gui")
        from PyQt5.QtCore import QSettings
        monkeypatch.setattr(gui, "QSettings", lambda *a: QSettings(
            str(tmp_path / "s.ini"), QSettings.IniFormat))
        topo = build("tree", n_subnets=2, seed=6)
        w = gui.MainWindow(topo)
        w.show()
        qapp.processEvents()
        return gui, w

    def test_window_scene_and_tree(self, qapp, tmp_path, monkeypatch):
        gui, w = self._window(qapp, tmp_path, monkeypatch)
        sc = w._scene
        assert len(sc.nodes) == len(w.topology.devices)
        assert len(sc.edges) == len(w.topology.links)
        assert w.tree.topLevelItemCount() >= 2
        w._modified = False
        w.close()

    def test_search_filter_and_layouts(self, qapp, tmp_path, monkeypatch):
        gui, w = self._window(qapp, tmp_path, monkeypatch)
        w.search_edit.setText("10.1.0.")
        qapp.processEvents()
        assert w._search_hits and all(
            w._scene.nodes[h].highlighted for h in w._search_hits)
        w.search_edit.clear()
        w.type_actions["router"].setChecked(False)
        assert not any(n.isVisible() for n in w._scene.nodes.values()
                       if n.device.device_type == "router")
        w._set_all_types(True)
        for mode in ("tree-lr", "organic", "tree"):
            w._set_layout(mode)
            assert find_overlaps(positions(w.topology)) == []
        w._modified = False
        w.close()

    def test_edit_operations(self, qapp, tmp_path, monkeypatch):
        gui, w = self._window(qapp, tmp_path, monkeypatch)
        ids = [n for n, d in w.topology.devices.items() if not d.is_virtual]
        w._scene.add_link_between(ids[2], ids[6])
        assert w.topology.graph.has_edge(ids[2], ids[6])
        w._scene.delete_edge(ids[2], ids[6])
        assert not w.topology.graph.has_edge(ids[2], ids[6])
        w._scene.merge_nodes(ids[0], ids[1])
        assert ids[1] not in w.topology.devices
        w._scene.delete_device(ids[3])
        assert ids[3] not in w.topology.devices
        assert len(w._scene.nodes) == len(w.topology.devices)
        w._modified = False
        w.close()

    def test_export_menu_has_excel_ip_list(self, qapp, tmp_path, monkeypatch):
        gui, w = self._window(qapp, tmp_path, monkeypatch)
        titles = [a.text() for a in w.export_menu.actions()]
        assert "Список IP-адресов Excel" in titles
        pytest.importorskip("openpyxl")
        target = tmp_path / "gui_ips.xlsx"
        monkeypatch.setattr(gui.QFileDialog, "getSaveFileName",
                            staticmethod(lambda *a, **k: (str(target), "")))
        action = next(a for a in w.export_menu.actions()
                      if a.text() == "Список IP-адресов Excel")
        action.trigger()
        assert target.exists() and target.stat().st_size > 0
        w._modified = False
        w.close()

    def test_png_pdf_export(self, qapp, tmp_path, monkeypatch):
        gui, w = self._window(qapp, tmp_path, monkeypatch)
        png, pdf = tmp_path / "t.png", tmp_path / "t.pdf"
        w.export_png(str(png))
        w.export_pdf(str(pdf))
        assert png.read_bytes()[:4] == b"\x89PNG"
        assert pdf.read_bytes()[:4] == b"%PDF"
        assert pdf.stat().st_size < 3_000_000, "PDF должен быть векторным"
        w._modified = False
        w.close()
