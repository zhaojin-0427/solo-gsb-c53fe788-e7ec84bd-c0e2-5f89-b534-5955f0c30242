"""解析器与影响分析的回归测试。

运行：``python -m pytest -q``（需 pytest）。
也可直接执行：``python tests/test_engine.py``。
"""
import random

import dns.name
import dns.rdatatype

from app.zone import parse_zone, ZoneError
from app.resolver import Resolver
from app.diff import (
    analyze, answer_signature, rel_labels, abs_name, Cone,
)

ORIGIN = "ex."


def zone(text):
    return parse_zone(text, ORIGIN, label="z")


def res(pz):
    return Resolver(pz)


def ask(r, name, qtype):
    qn = dns.name.from_text(name, origin=r.origin)
    return r.resolve(qn, dns.rdatatype.from_text(qtype))


# ---------------------------------------------------------------- 解析校验

def test_reject_unsupported_type():
    text = (
        "$ORIGIN ex.\n$TTL 60\n@ SOA ns hm 1 1 1 1 1\n NS ns\nns A 1.1.1.1\n"
        "mail MX 10 mail\n"
    )
    try:
        zone(text)
        assert False, "应拒绝 MX"
    except ZoneError:
        pass


def test_reject_out_of_zone_owner():
    text = (
        "$ORIGIN ex.\n$TTL 60\n@ SOA ns hm 1 1 1 1 1\n NS ns\nns A 1.1.1.1\n"
        "host.other. A 1.1.1.2\n"
    )
    try:
        zone(text)
        assert False, "应拒绝越区属主"
    except ZoneError:
        pass


def test_reject_external_reference():
    text = (
        "$ORIGIN ex.\n$TTL 60\n@ SOA ns hm 1 1 1 1 1\n NS ns\nns A 1.1.1.1\n"
        "www CNAME target.external.\n"
    )
    try:
        zone(text)
        assert False, "应拒绝外部 CNAME 引用"
    except ZoneError:
        pass


def test_reject_cname_with_other_data():
    text = (
        "$ORIGIN ex.\n$TTL 60\n@ SOA ns hm 1 1 1 1 1\n NS ns\nns A 1.1.1.1\n"
        "www CNAME host\nwww A 1.1.1.2\nhost A 1.1.1.3\n"
    )
    try:
        zone(text)
        assert False, "应拒绝 CNAME 与其他类型共存"
    except ZoneError:
        pass


def test_reject_delegation_with_data_below():
    text = (
        "$ORIGIN ex.\n$TTL 60\n@ SOA ns hm 1 1 1 1 1\n NS ns\nns A 1.1.1.1\n"
        "sub NS ns.sub\nns.sub A 2.2.2.2\nstray.sub A 3.3.3.3\n"
    )
    try:
        zone(text)
        assert False, "切点之下除 glue 外不允许数据"
    except ZoneError:
        pass


def test_reject_apex_dname():
    text = (
        "$ORIGIN ex.\n$TTL 60\n@ SOA ns hm 1 1 1 1 1\n NS ns\nns A 1.1.1.1\n"
        "@ DNAME target\n"
    )
    try:
        zone(text)
        assert False, "顶点 DNAME 非法"
    except ZoneError:
        pass


# ---------------------------------------------------------------- 解析行为

BASE = """$ORIGIN ex.
$TTL 60
@ SOA ns hm 1 7200 3600 1209600 60
  NS ns
  NS ns2
ns A 192.0.2.1
ns2 AAAA 2001:db8::2
www CNAME host
host A 192.0.2.10
host AAAA 2001:db8::10
*.wild A 192.0.2.77
ent A 192.0.2.20
deep.ent A 192.0.2.21
d DNAME dt
dt A 192.0.2.90
sub NS ns.sub
ns.sub A 192.0.2.53
lo CNAME lo2
lo2 CNAME lo
"""


def test_exact_and_cname_chain():
    r = res(zone(BASE))
    a = ask(r, "host", "A")
    assert a.termination == "exact" and a.rcode == "NOERROR"
    a = ask(r, "www", "A")
    assert a.termination == "exact"
    kinds = [h.kind for h in a.hops]
    assert kinds == ["CNAME"]
    assert a.answer[0].rdata.target == dns.name.from_text("host.ex.")


def test_nodata_vs_ent_vs_nxdomain():
    r = res(zone(BASE))
    assert ask(r, "host", "NS").termination == "noerror_nodata"
    assert ask(r, "x.ent", "A").termination == "ent_nodata"
    assert ask(r, "nothing", "A").termination == "nxdomain"


def test_wildcard_expansion_and_deep_nonmatch():
    r = res(zone(BASE))
    a = ask(r, "x.wild", "A")
    assert a.termination == "wildcard_expansion"
    assert a.wildcard_source == dns.name.from_text("*.wild.ex.")
    assert a.answer[0].rdata.address == "192.0.2.77"
    # 多一层且中间无真实名称：通配不扩展（RFC 4592 closest encloser）。
    assert ask(r, "a.b.wild", "A").termination == "nxdomain"


def test_dname_rewrite_and_synthesis():
    r = res(zone(BASE))
    a = ask(r, "x.d", "A")
    # x.d 经 DNAME 合成 CNAME 指向 x.dt；x.dt 本身无记录，链末端为 NODATA，
    # 但应答里仍含合成 CNAME（在前）与真实 DNAME（在后）。
    assert a.hops[0].kind == "DNAME"
    assert a.answer[0].rdtype == dns.rdatatype.CNAME
    assert a.answer[1].rdtype == dns.rdatatype.DNAME
    assert a.answer[0].rdata.target == dns.name.from_text("x.dt.ex.")
    # x.d 的最近真实祖先是 d（空非终结点路径），链末端名称 x.dt 不存在，
    # 故终止原因为空非终结点 NODATA，但应答含完整 DNAME 合成链。
    assert a.termination == "ent_nodata"
    # 精确名 d 不触发 DNAME 合成。
    assert ask(r, "d", "A").termination == "noerror_nodata"
    # 目标子树存在记录时，沿 DNAME 链一路命中。
    b2 = zone(BASE + "x.dt A 192.0.2.95\n")
    a2 = Resolver(b2).resolve(
        dns.name.from_text("x.d.ex."), dns.rdatatype.A)
    assert a2.termination == "exact"
    assert any(
        x.rdtype == dns.rdatatype.A and x.rdata.address == "192.0.2.95"
        for x in a2.answer
    )


def test_delegation_referral():
    r = res(zone(BASE))
    for n in ("sub", "x.sub", "ns.sub"):
        a = ask(r, n, "A")
        assert a.termination == "delegation"
        assert a.aa is False
        assert a.authority[0].rdtype == dns.rdatatype.NS
    # glue 在 additional
    a = ask(r, "sub", "A")
    assert any(x.rdtype == dns.rdatatype.A and
               x.rdata.address == "192.0.2.53" for x in a.additional)


def test_alias_loop_is_marked_not_errored():
    r = res(zone(BASE))
    a = ask(r, "lo", "A")
    assert a.termination == "alias_loop"
    assert a.rcode == "NOERROR"
    assert len(a.answer) >= 2


# ---------------------------------------------------------------- 影响模式

def _suffix(child, parent):
    return child == parent or (
        len(child) > len(parent)
        and child[len(child) - len(parent):] == parent
    )


def _depth(child, parent):
    return len(child) - len(parent) if _suffix(child, parent) else -1


def _name_in(labels, cone: Cone):
    P, Q = labels, cone.labels
    if cone.kind == "exact":
        return P == Q
    if cone.kind == "star":
        return _depth(P, Q) == 1
    return _depth(P, Q) >= 0


def _in_pattern(labels, p):
    return _name_in(labels, p.scope) and not any(
        _name_in(labels, e) for e in p.exclude
    )


def assert_sound(b, c, qtype, vocab, rounds=3000):
    rb, rc = res(b), res(c)
    qt = dns.rdatatype.from_text(qtype)
    patterns = analyze(b, c, [qt])[0].patterns
    random.seed(7)
    for _ in range(rounds):
        labs = tuple(random.choice(vocab)
                     for _ in range(random.randint(0, 5)))
        qn = abs_name(labs, b.origin)
        changed = answer_signature(rb.resolve(qn, qt)) != answer_signature(
            rc.resolve(qn, qt))
        members = [i for i, p in enumerate(patterns)
                   if _in_pattern(labs, p)]
        if changed:
            assert len(members) == 1, (qtype, labs, members)
        else:
            assert members == [], (qtype, labs, members)
    for p in patterns:
        assert _in_pattern(rel_labels(p.witness, b.origin), p)


CHANGE_B = """$ORIGIN ex.
$TTL 60
@ SOA ns hm 1 1 1 1 1
  NS ns
ns A 192.0.2.1
www A 192.0.2.10
api A 192.0.2.20
old CNAME www
sub A 10.0.0.1
child.sub A 10.0.0.2
dlg NS ns.dlg
ns.dlg A 192.0.2.53
*.wild A 192.0.2.77
d DNAME dt
dt A 192.0.2.90
"""

CHANGE_C = """$ORIGIN ex.
$TTL 60
@ SOA ns hm 2 1 1 1 1
  NS ns
ns A 192.0.2.1
www A 192.0.2.11
api AAAA 2001:db8::20
new A 192.0.2.30
old CNAME www
sub A 10.0.0.1
child.sub A 10.0.0.2
dlg NS ns.dlg
ns.dlg A 192.0.2.53
*.wild A 192.0.2.78
d DNAME dt
dt A 192.0.2.91
leaf.dt A 192.0.2.92
"""

VOCAB = ["www", "api", "new", "old", "sub", "child", "wild", "d", "dt",
         "leaf", "ns", "dlg", "x", "y", "z", "*", "w-0", "ww-0",
         "w-5", "w-9", "foo", "bar"]


def test_patterns_sound_all_types():
    b, c = parse_zone(CHANGE_B, ORIGIN, label="b"), parse_zone(
        CHANGE_C, ORIGIN, label="c")
    for t in ("A", "AAAA", "NS", "CNAME", "DNAME", "SOA"):
        assert_sound(b, c, t, VOCAB)


def test_known_a_changes():
    b, c = parse_zone(CHANGE_B, ORIGIN, label="b"), parse_zone(
        CHANGE_C, ORIGIN, label="c")
    scopes = {p.scope.render()
              for p in analyze(b, c, [dns.rdatatype.A])[0].patterns}
    assert "www" in scopes
    assert "api" in scopes          # A 删除 → NODATA
    assert "new" in scopes          # 新增
    assert "*.wild" in scopes       # 通配地址变更
    assert "dt" in scopes           # DNAME 目标 A 变更
    assert "leaf.d" in scopes       # DNAME 拉回覆盖未列名


def test_dname_target_deep_unlisted_covered():
    b = parse_zone(
        "$ORIGIN ex.\n$TTL 60\n@ SOA ns hm 1 1 1 1 1\n NS ns\nns A 1.1.1.1\n"
        "d DNAME dt\ndt A 5.5.5.5\n", ORIGIN, label="b")
    c = parse_zone(
        "$ORIGIN ex.\n$TTL 60\n@ SOA ns hm 2 1 1 1 1\n NS ns\nns A 1.1.1.1\n"
        "d DNAME dt\ndt A 5.5.5.5\na.b.dt A 9.9.9.9\n", ORIGIN, label="c")
    scopes = {p.scope.render()
              for p in analyze(b, c, [dns.rdatatype.A])[0].patterns}
    assert "a.b.d" in scopes and "a.b.dt" in scopes


def test_identical_zones_no_patterns():
    b = parse_zone(CHANGE_B, ORIGIN, label="b")
    c = parse_zone(CHANGE_B, ORIGIN, label="c")
    for t in ("A", "NS"):
        assert analyze(b, c, [dns.rdatatype.from_text(t)])[0].patterns == []


if __name__ == "__main__":
    import inspect
    import sys
    fails = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("PASS", name)
            except Exception as e:  # noqa: BLE001
                fails += 1
                print("FAIL", name, repr(e))
    sys.exit(1 if fails else 0)
