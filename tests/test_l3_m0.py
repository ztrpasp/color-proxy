"""L3 隧道模式 M0 单元测试（docs/design-l3-v2.md §11 M0 / §3.4 测试向量）。

覆盖三块：
1. 服务级规范串与 L_sid —— §3.4 的全部测试向量，两端实现自检的基准；
2. ``load[0]`` 掩码扩宽后的取值（含 v1 向后兼容）；
3. 提供端/消费端 ``l3`` 段的配置校验 —— §9.1 / §9.2 要求的 fail-fast。

可用 ``python -m pytest tests/test_l3_m0.py`` 运行，
也可直接 ``python tests/test_l3_m0.py`` 运行（无需 pytest）。
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from colorproxy.config import load_config
from colorproxy.consumer.config import load_consumer_config
from colorproxy.consumer.state import ConsumerState
from colorproxy.protocol.constants import WEB_MSG_TYPE_MASK, LoadFlag, WebMsgType
from colorproxy.protocol.sid import (
    lsid_from_service,
    nid_to_bytes,
    service_canonical,
    sid_hex_from_service,
)
from colorproxy.state import ProviderState

#: docs/design-l3-v2.md §3.4 的测试向量（D12 新格式）
SERVICE_VECTORS = {
    "tcp://172.10.0.2:8000": "8ae37891ae4a7199ceca8962c12061637ca1f560",
    "tcp://172.10.0.2:21": "52ae3dfb6e1b4b01dd67c119c930f4e6ac571e80",
    "tcp://172.10.0.2:3306": "92acf1bac92fe6396f990b933a2a8eb3f49f3fd3",
    "udp://172.10.0.2:5004": "dfe05b09001a47cce837108c500214c65019da3c",
    "tcp://172.10.0.2:0": "4b2b1ec837331cc15ca4b331f185e30770c19677",
    "tcp://172.10.0.2:50000": "550d2ca4674c55207d6d481edfad6ad00b041eaf",
    "tcp://172.10.0.2:50001": "10be579aad63dddcb358c5be113a91f18bdfd15f",
}

PROVIDER_NID = 0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1
CONSUMER_NID = 0xB2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2


# ---------------------------------------------------------------- §3 规范串 / L_sid

def test_service_vectors_match_design_doc() -> None:
    """§3.4 的全部向量必须逐条命中（两端一致性的基准）。"""
    for canonical, expected_lsid in SERVICE_VECTORS.items():
        proto, rest = canonical.split("://", 1)
        ip, port = rest.rsplit(":", 1)
        assert service_canonical(proto, ip, int(port)) == canonical
        got = lsid_from_service(proto, ip, int(port)).hex()
        assert got == expected_lsid, f"{canonical}: 期望 {expected_lsid}，实得 {got}"


def test_service_canonical_normalizes_and_rejects() -> None:
    """归一化集中在 service_canonical，非法写法一律抛 ValueError（§3.1）。"""
    # 大小写与空白被归一化
    assert service_canonical("TCP", " 172.10.0.2 ", 8000) == "tcp://172.10.0.2:8000"
    # 端口接受字符串形式的整数（JSON 里写成 "8000" 也能过）
    assert service_canonical("tcp", "172.10.0.2", "8000") == "tcp://172.10.0.2:8000"

    for bad in [
        ("http", "172.10.0.2", 8000),     # 协议必须是 tcp/udp（与内容级隔离哈希域）
        ("tcp", "172.010.0.2", 8000),     # 前导零
        ("tcp", "not-an-ip", 8000),
        ("tcp", "172.10.0.2", 70000),     # 端口越界
        ("tcp", "172.10.0.2", -1),
    ]:
        try:
            service_canonical(*bad)
        except ValueError:
            continue
        raise AssertionError(f"{bad} 应当被拒绝但通过了")


def test_tcp_and_udp_are_different_services() -> None:
    """协议入串：同 ip:port 的 tcp 与 udp 是两个不同的 SID（§3.1）。"""
    assert lsid_from_service("tcp", "172.10.0.2", 5004) != lsid_from_service(
        "udp", "172.10.0.2", 5004
    )


def test_service_and_content_hash_domains_are_disjoint() -> None:
    """服务级串带 tcp/udp scheme、内容级带 http，故不会撞同一个 L_sid（§3.1）。"""
    from colorproxy.protocol.sid import lsid_from_url

    assert lsid_from_service("tcp", "172.10.0.2", 8000) != lsid_from_url(
        "http://172.10.0.2:8000"
    )


def test_sid_hex_from_service_is_72_hex_with_provider_nsid() -> None:
    sid = sid_hex_from_service(PROVIDER_NID, "tcp", "172.10.0.2", 8000)
    assert len(sid) == 72
    assert sid[:32] == nid_to_bytes(PROVIDER_NID).hex()
    assert sid[32:] == SERVICE_VECTORS["tcp://172.10.0.2:8000"]


# ---------------------------------------------------------------- §4.1 load[0]

def test_mask_widened_and_v1_values_unchanged() -> None:
    """掩码扩到 0xF0；v1 三个取值结果不变，L3 两个不再与 v1 混淆（§4.1）。"""
    assert WEB_MSG_TYPE_MASK == 0xF0
    for v1_type in (WebMsgType.TUNNEL, WebMsgType.HTTP_REQUEST, WebMsgType.HTTP_RESPONSE):
        load0 = v1_type | LoadFlag.LAST
        assert load0 & WEB_MSG_TYPE_MASK == v1_type

    # 旧掩码 0x30 之下 0x51 会被误判成 TUNNEL —— 这正是必须扩宽的原因
    down = WebMsgType.IP_DOWNSTREAM | LoadFlag.LAST   # 0x51
    assert down & 0x30 == WebMsgType.TUNNEL
    assert down & WEB_MSG_TYPE_MASK == WebMsgType.IP_DOWNSTREAM
    up = WebMsgType.IP_UPSTREAM | LoadFlag.LAST       # 0x41
    assert up & WEB_MSG_TYPE_MASK == WebMsgType.IP_UPSTREAM


# ---------------------------------------------------------------- §9 配置校验

def _write(data: dict) -> str:
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False, encoding="utf-8"
    )
    json.dump(data, handle)
    handle.close()
    return handle.name


def _provider_cfg(**l3_overrides) -> dict:
    l3 = {
        "enabled": True,
        "tun_ip": "10.99.1.254",
        "peer_routes": ["10.99.1.0/24"],
        "peers": [{"nid": f"{CONSUMER_NID:032x}", "tun_ip": "10.99.1.1"}],
        "services": [{"proto": "tcp", "ip": "172.10.0.2", "port": 8000}],
    }
    l3.update(l3_overrides)
    return {
        "nid": f"{PROVIDER_NID:032x}",
        "ipv4": "172.10.0.2",
        "rm_ipv4": "172.10.0.5",
        "services": [{"url": "http://172.10.0.2:8000/hello.html"}],
        "l3": l3,
    }


def _consumer_cfg(**l3_overrides) -> dict:
    l3 = {"enabled": True, "tun_ip": "10.99.1.1", "capture_routes": ["172.10.0.2/32"]}
    l3.update(l3_overrides)
    return {
        "nid": f"{CONSUMER_NID:032x}",
        "ipv4": "10.10.0.2",
        "rm_ipv4": "10.10.0.1",
        "l3": l3,
    }


def _expect_reject(loader, data: dict, reason: str) -> None:
    path = _write(data)
    try:
        loader(path)
    except ValueError:
        return
    finally:
        os.unlink(path)
    raise AssertionError(f"应当拒绝启动：{reason}")


def test_provider_l3_config_loads_and_normalizes() -> None:
    path = _write(_provider_cfg())
    try:
        config = load_config(path)
    finally:
        os.unlink(path)
    assert config.l3.enabled
    assert config.l3.tun_mtu == 1280 and config.l3.mss_clamp == 1240  # §9.1 缺省
    assert config.l3.services[0].canonical == "tcp://172.10.0.2:8000"
    assert config.l3.peer_by_tun_ip("10.99.1.1").nid == CONSUMER_NID


def test_provider_l3_config_rejects_bad_entries() -> None:
    _expect_reject(load_config, _provider_cfg(peers=[]), "enabled 但 peers 为空")
    _expect_reject(load_config, _provider_cfg(services=[]), "enabled 但 services 为空")
    _expect_reject(
        load_config,
        _provider_cfg(services=[{"proto": "tcp", "ip": "172.010.0.2", "port": 8000}]),
        "服务 IP 有前导零",
    )
    _expect_reject(
        load_config,
        _provider_cfg(services=[
            {"proto": "tcp", "ip": "172.10.0.2", "port": 8000},
            {"proto": "TCP", "ip": "172.10.0.2", "port": "8000"},
        ]),
        "两条服务归一化后规范串重复（同一个 SID）",
    )
    _expect_reject(
        load_config,
        _provider_cfg(peers=[
            {"nid": f"{CONSUMER_NID:032x}", "tun_ip": "10.99.1.1"},
            {"nid": f"{CONSUMER_NID + 1:032x}", "tun_ip": "10.99.1.1"},
        ]),
        "两个消费端 tun_ip 重复（§2.2 全局唯一）",
    )
    _expect_reject(
        load_config,
        _provider_cfg(peers=[{"nid": f"{CONSUMER_NID:032x}", "tun_ip": "10.88.0.1"}]),
        "消费端 tun_ip 不在 peer_routes 覆盖的网段内",
    )
    _expect_reject(
        load_config,
        _provider_cfg(peers=[{"nid": f"{CONSUMER_NID:032x}", "tun_ip": "10.99.1.254"}]),
        "消费端 tun_ip 与本机 tun_ip 相同",
    )
    _expect_reject(load_config, _provider_cfg(mss_clamp=1280), "mss_clamp > tun_mtu−40")


def test_consumer_l3_config_enforces_route_isolation() -> None:
    path = _write(_consumer_cfg())
    try:
        config = load_consumer_config(path)
    finally:
        os.unlink(path)
    assert config.l3.capture_routes == ("172.10.0.2/32",)
    assert config.l3.tunnel_timeout_sec == 5.0
    assert config.l3.get_per_connection is True, "D19 默认开：ACL 要按连接生效"
    assert config.l3.udp_flow_idle_sec == 60.0

    _expect_reject(
        load_consumer_config, _consumer_cfg(udp_flow_idle_sec=0), "udp_flow_idle_sec 不是正数"
    )

    _expect_reject(
        load_consumer_config,
        _consumer_cfg(capture_routes=["172.10.0.0/24"]),
        "capture_route 不是 /32（会吞掉对端域的 RM，§2.4 第 1 条）",
    )
    _expect_reject(
        load_consumer_config,
        _consumer_cfg(capture_routes=["10.10.0.1/32"]),
        "capture_route 覆盖了本域 RM（链路死锁，§2.4）",
    )
    _expect_reject(
        load_consumer_config, _consumer_cfg(capture_routes=[]), "enabled 但无 capture_routes"
    )


def test_shipped_configs_are_consistent() -> None:
    """随仓库发布的两份配置必须能加载，且两端地址/SID 对得上（§9.3 第 1、2 条）。"""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    provider = load_config(os.path.join(root, "config.json"))
    consumer = load_consumer_config(os.path.join(root, "config-consumer.json"))

    # 提供端发布的 URL 与消费端预载的 URL 必须哈希一致，否则永远匹配不上
    from colorproxy.protocol.sid import sid_hex_from_url

    published = {sid_hex_from_url(provider.nid, svc.url) for svc in provider.services}
    # D20：L3 端点按 URL 发布的内容级 SID 同样可以被预载（没有 RM 时的降级路径）
    published |= {sid_hex_from_url(provider.nid, url)
                  for svc in provider.l3.services for url in svc.content_urls}
    for entry in consumer.sids:
        sid = sid_hex_from_url(entry.provider_nid, entry.url)
        assert sid in published, f"消费端预载的 {entry.url} 在提供端未发布（SID 对不上）"

    # 所有 origin 都应指向提供端自己，而不是 RM 那台机器（§9.3 第 2 条）
    for svc in provider.services:
        assert svc.origin_host == provider.ipv4, f"{svc.url} 的 origin 指向了 {svc.origin_host}"

    # 消费端的 tun 地址必须与提供端 peers[] 的登记一致（§9.2，D14）
    peer = provider.l3.peer_by_tun_ip(consumer.l3.tun_ip)
    assert peer is not None, (
        f"消费端 l3.tun_ip({consumer.l3.tun_ip}) 未登记在提供端 peers[]，"
        "上行包会被 src_bind_drop 全丢"
    )
    assert peer.nid == consumer.nid, "peers[] 里该 tun_ip 绑的 NID 与消费端 nid 不一致"

    # 消费端声明为 HTTP 的端点，提供端必须按 URL 发布过（D20）；否则每个请求都 http_url_miss
    http_endpoints = {(svc.proto, svc.ip, svc.port): svc
                      for svc in provider.l3.services if svc.app == "http"}
    for app in consumer.l3.app_services:
        svc = http_endpoints.get(app.endpoint)
        assert svc is not None and svc.paths, (
            f"消费端把 {app.endpoint} 声明为 HTTP，提供端却没有为它发布 paths"
        )


# ---------------------------------------------------------------- 两张服务表

def test_provider_state_keeps_two_service_tables() -> None:
    """v1 与 L3 的服务表并列，分派靠 SID 落在哪张表（§4.1，D13）。"""
    path = _write(_provider_cfg())
    try:
        config = load_config(path)
    finally:
        os.unlink(path)
    state = ProviderState(config)

    l3_service = config.l3.services[0]
    l3_sid = sid_hex_from_service(config.nid, l3_service.proto, l3_service.ip, l3_service.port)
    state.add_l3_service(l3_sid, l3_service)

    assert state.get_l3_service(l3_sid) is l3_service
    assert state.get_service(l3_sid) is None, "L3 的 SID 不应出现在 Web 服务表里"
    assert state.peer_tun_ip(CONSUMER_NID) == "10.99.1.1"
    assert state.peer_nid_by_tun_ip("10.99.1.1") == CONSUMER_NID
    assert state.peer_nid_by_tun_ip("10.99.1.9") is None


def test_provider_state_reverse_lookup_by_endpoint_with_wildcard() -> None:
    """回程按内层源三元组反推 SID，含通配回退（§7.2 回送第 2 步，D14）。"""
    cfg_data = _provider_cfg(services=[
        {"proto": "tcp", "ip": "172.10.0.2", "port": 21},
        {"proto": "tcp", "ip": "172.10.0.2", "port": 0},
    ])
    path = _write(cfg_data)
    try:
        config = load_config(path)
    finally:
        os.unlink(path)
    state = ProviderState(config)
    for svc in config.l3.services:
        state.add_l3_service(
            sid_hex_from_service(config.nid, svc.proto, svc.ip, svc.port), svc
        )

    exact = state.find_l3_service_for_endpoint("tcp", "172.10.0.2", 21)
    assert exact is not None and exact[1].port == 21, "精确端口应优先命中"

    # 被动 FTP 的临时端口只能靠通配项命中
    wildcard = state.find_l3_service_for_endpoint("tcp", "172.10.0.2", 50123)
    assert wildcard is not None and wildcard[1].is_wildcard_port

    assert state.find_l3_service_for_endpoint("udp", "172.10.0.2", 21) is None
    assert state.find_l3_service_for_endpoint("tcp", "172.10.0.9", 21) is None


def test_consumer_lookup_by_service_falls_back_to_wildcard() -> None:
    """消费端查表两级回退：精确端口 → 通配 :0 → 未命中（§3.3 / §7.1 上行第 5 步）。"""
    path = _write(_consumer_cfg())
    try:
        config = load_consumer_config(path)
    finally:
        os.unlink(path)
    state = ConsumerState(config)

    exact_sid = sid_hex_from_service(PROVIDER_NID, "tcp", "172.10.0.2", 21)
    wildcard_sid = sid_hex_from_service(PROVIDER_NID, "tcp", "172.10.0.2", 0)
    state.add_sid(exact_sid)
    state.add_sid(wildcard_sid)

    assert state.lookup_by_service("tcp", "172.10.0.2", 21) == exact_sid
    assert state.lookup_by_service("tcp", "172.10.0.2", 50123) == wildcard_sid
    assert state.lookup_by_service("udp", "172.10.0.2", 21) is None
    assert state.lookup_by_service("tcp", "172.10.0.9", 21) is None


def test_static_services_preload_yields_the_same_sid_as_the_provider_publishes() -> None:
    """``l3.static_services[]`` 算出的 SID 必须与提供端 ANN 发布的逐字节一致。

    这是 SID 表未就绪时的降级路径（§9.2）。算错一个字节的症状是"SID 永远对不上"、
    每个包都 sid_miss，而两端配置看着都对——正是最难查的那一类，故用向量钉住。
    """
    import json
    import tempfile
    from colorproxy.consumer.config import load_consumer_config
    from colorproxy.protocol.sid import sid_hex_from_service

    provider_nid = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
    document = {
        "nid": "b2" * 16, "ipv4": "10.10.0.2", "rm_ipv4": "10.10.0.1",
        "l3": {
            "enabled": True, "tun_ip": "10.99.1.1",
            "capture_routes": ["172.10.9.2/32"],
            "static_services": [
                {"proto": "tcp", "ip": "172.10.9.2", "port": 8000,
                 "provider_nid": provider_nid, "desc": "端点级 HTTP"},
            ],
        },
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                     encoding="utf-8") as handle:
        json.dump(document, handle)
        path = handle.name
    config = load_consumer_config(path)

    assert len(config.l3.static_services) == 1
    service = config.l3.static_services[0]
    assert (service.proto, service.ip, service.port) == ("tcp", "172.10.9.2", 8000)
    assert sid_hex_from_service(service.provider_nid, service.proto, service.ip,
                                service.port) == sid_hex_from_service(
        int(provider_nid, 16), "tcp", "172.10.9.2", 8000)


def test_static_services_normalise_and_fail_fast() -> None:
    """归一化与 fail-fast：前导零 IP、非 tcp/udp、缺 provider_nid 一律拒绝启动。"""
    import json
    import tempfile
    from colorproxy.consumer.config import load_consumer_config

    def _load(entry):
        document = {
            "nid": "b2" * 16, "ipv4": "10.10.0.2", "rm_ipv4": "10.10.0.1",
            "l3": {"enabled": True, "tun_ip": "10.99.1.1",
                   "capture_routes": ["172.10.9.2/32"], "static_services": [entry]},
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         encoding="utf-8") as handle:
            json.dump(document, handle)
            path = handle.name
        return load_consumer_config(path)  # 必须等文件关闭后再读，否则读到空文件

    good = "a1" * 16
    # 端口给成字符串是人手写配置时的常见写法，必须归一化而不是算出另一个哈希
    config = _load({"proto": "tcp", "ip": "172.10.9.2", "port": "8000",
                    "provider_nid": good})
    assert config.l3.static_services[0].port == 8000

    for bad, why in (
        ({"proto": "http", "ip": "172.10.9.2", "port": 8000, "provider_nid": good},
         "协议必须是 tcp/udp"),
        ({"proto": "tcp", "ip": "172.010.9.2", "port": 8000, "provider_nid": good},
         "前导零 IP"),
        ({"proto": "tcp", "ip": "172.10.9.2", "port": 8000}, "缺 provider_nid"),
    ):
        try:
            _load(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"应当拒绝启动：{why}")


def _run_all() -> int:
    funcs = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in funcs:
        try:
            fn()
            print(f"  PASS {fn.__name__}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  FAIL {fn.__name__}: {exc!r}")
    print(f"\n{len(funcs) - failed}/{len(funcs)} passed")
    return failed


if __name__ == "__main__":
    raise SystemExit(_run_all())
